#!/usr/bin/env python3
# Copyright (c) 2026 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
# SPDX-License-Identifier: Apache-2.0

"""
VM Operator Negative Testing / Fuzzing Framework (v1alpha5 & v1alpha6).

Data-driven engine: iterates over a TestRegistry of spec permutations, applies
VM (and optional VMClass) manifests, captures status.conditions and events,
categorizes failures, and produces an HTML report.

Architecture:
  - ManifestFactory: builds VM/VMClass YAML for the chosen API version.
  - TestRegistry: list of test entries (id, category, vm_spec_override, class_spec_override).
  - KubeRunner: apply / watch / delete via SupervisorClient (or kubernetes client); captures conditions + events.
  - Categorizer: maps K8s Reasons to VALIDATION | PLACEMENT | POWER_ON | GUEST_TIMEOUT | INFRA.
  - Reporter: standalone HTML with CSS tabs/filters and links to hack/artifacts/{test_id}/.

Usage:
  # Direct Supervisor mode — if you already have the control-plane IP & password:
  python hack/vmop_fuzzer.py --vmi <vmi-name> --supervisor-ip <sv-ip> --supervisor-password <pwd> --namespace <ns>

  # vCenter mode — credentials discovered automatically via decryptK8Pwd.py:
  python hack/vmop_fuzzer.py --vmi <vmi-name> --vcenter <vc-ip> --vcenter-password <pwd> --namespace <ns>

  # Both modes accept --api-version, --storage-class, --vm-class, --timeout, etc.
  # Add --validate-configspec or --capture-vcenter-tasks to enable vCenter features
  # (these require --vcenter/--vcenter-password even in direct Supervisor mode).

Requirements:
  pip install pyyaml paramiko          # always required
  pip install pyVmomi                  # required for --validate-configspec / --capture-vcenter-tasks / vCenter mode
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import re
import ssl

import yaml

# Optional third-party dependencies — fail fast only when actually used.
try:
    import paramiko as _paramiko  # pip install paramiko
    _HAS_PARAMIKO = True
except ImportError:
    _paramiko = None  # type: ignore[assignment]
    _HAS_PARAMIKO = False

try:
    from pyVim.connect import SmartConnect as _SmartConnect, Disconnect as _Disconnect  # pip install pyVmomi
    _HAS_PYVMOMI = True
except ImportError:
    _SmartConnect = _Disconnect = None  # type: ignore[assignment]
    _HAS_PYVMOMI = False

_HACK_DIR = Path(__file__).resolve().parent

DEFAULT_VCENTER_USER = "administrator@vsphere.local"


# -----------------------------------------------------------------------------
# SupervisorClient — SSH client for the WCP Supervisor control-plane node
# -----------------------------------------------------------------------------
class SupervisorClient:
    """SSH client for the WCP Supervisor control-plane node.

    Provides ``run_kubectl`` (with automatic SSH reconnect) and
    ``namespace_exists`` — all that the fuzzer needs from the Supervisor.

    Requires: ``pip install paramiko``
    """

    def __init__(self, host: str, password: str, user: str = "root") -> None:
        if not _HAS_PARAMIKO:
            raise RuntimeError(
                "paramiko is required for Supervisor SSH access. "
                "pip install paramiko"
            )
        self.host = host
        self.user = user
        self.password = password
        self.ssh: Any = None

    def connect(self) -> None:
        print(f"Connecting to Supervisor {self.host} via SSH...")
        self._open_ssh()
        print("  Connected to Supervisor")

    def _open_ssh(self) -> None:
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
        client = _paramiko.SSHClient()
        client.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            username=self.user,
            password=self.password,
            look_for_keys=False,
            allow_agent=False,
        )
        self.ssh = client

    def disconnect(self) -> None:
        if self.ssh:
            self.ssh.close()
            self.ssh = None
            print("Disconnected from Supervisor")

    def run_kubectl(self, args: str, check: bool = True) -> tuple[str, str, int]:
        """Run ``kubectl <args>`` over SSH. Returns (stdout, stderr, exit_code)."""
        cmd = f"kubectl {args}"
        stdout_str = stderr_str = ""
        exit_code = 1
        # SSHException is a subclass of Exception, not OSError, so capture all
        # three common disconnect types.
        _exc = (_paramiko.SSHException, EOFError, OSError)
        for attempt in range(2):
            try:
                _, stdout, stderr = self.ssh.exec_command(cmd)
                exit_code = stdout.channel.recv_exit_status()
                stdout_str = stdout.read().decode()
                stderr_str = stderr.read().decode()
                break
            except _exc as e:
                if attempt == 0:
                    print(f"  SSH connection lost ({e}), reconnecting...")
                    self._open_ssh()
                else:
                    raise RuntimeError(
                        f"SSH connection failed after reconnect: {e}"
                    ) from e
        if check and exit_code != 0:
            raise RuntimeError(f"kubectl command failed: {cmd}\n{stderr_str}")
        return stdout_str, stderr_str, exit_code

    def namespace_exists(self, namespace: str) -> bool:
        _, _, rc = self.run_kubectl(f"get namespace {namespace}", check=False)
        return rc == 0


# -----------------------------------------------------------------------------
# VCenterClient — minimal vCenter client for credential discovery + pyVmomi SI
# -----------------------------------------------------------------------------
class VCenterClient:
    """Minimal vCenter client used by the fuzzer for two purposes:

    1. **Supervisor credential discovery** (vCenter mode):
       SSH to vCenter as root and run ``decryptK8Pwd.py`` to obtain the
       Supervisor control-plane IP and root password.

    2. **pyVmomi ServiceInstance** (``--validate-configspec``,
       ``--capture-vcenter-tasks``):
       ``self.si`` is the raw ``vim.ServiceInstance`` used by
       ``ConfigSpecValidator`` and ``get_vcenter_tasks``.

    Requires: ``pip install pyVmomi paramiko``
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        root_password: str | None = None,
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.root_password = root_password or password
        self.si: Any = None   # vim.ServiceInstance (pyVmomi)
        self.ssh: Any = None  # paramiko.SSHClient (vCenter root SSH)

    def connect(self, ssh: bool = True) -> None:
        """Connect to vCenter via SOAP API and optionally via SSH.

        ``ssh=True``  — also open a root SSH session for ``get_supervisor_credentials``.
        ``ssh=False`` — SOAP only (``self.si``); used when vCenter is needed
                       only for pyVmomi features, not credential discovery.
        """
        if not _HAS_PYVMOMI:
            raise RuntimeError(
                "pyVmomi is required for vCenter mode. pip install pyVmomi"
            )
        print(f"Connecting to vCenter {self.host}...")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.si = _SmartConnect(
            host=self.host,
            user=self.user,
            pwd=self.password,
            sslContext=ctx,
        )
        print("  Connected to vCenter via SOAP API")
        if ssh:
            self._create_ssh_session()

    def _create_ssh_session(self) -> None:
        if not _HAS_PARAMIKO:
            raise RuntimeError(
                "paramiko is required for vCenter SSH access. pip install paramiko"
            )
        print("  Connecting to vCenter via SSH (root)...")
        client = _paramiko.SSHClient()
        client.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            username="root",
            password=self.root_password,
            look_for_keys=False,
            allow_agent=False,
        )
        self.ssh = client
        print("  Connected to vCenter via SSH")

    def disconnect(self) -> None:
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
            self.ssh = None
        if self.si:
            _Disconnect(self.si)
            self.si = None
            print("Disconnected from vCenter")

    def get_supervisor_credentials(self) -> tuple[str, str]:
        """Retrieve Supervisor IP and root password via ``decryptK8Pwd.py``.

        Runs ``/usr/lib/vmware-wcp/decryptK8Pwd.py`` on the vCenter node over
        SSH and parses ``IP: <ip>`` / ``PWD: <pwd>`` from its output.
        """
        print("Retrieving Supervisor credentials from vCenter...")
        _, stdout, _ = self.ssh.exec_command(
            "/usr/lib/vmware-wcp/decryptK8Pwd.py"
        )
        output = stdout.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code == 0 and output:
            sv_ip = sv_pwd = None
            for line in output.strip().splitlines():
                line = line.strip()
                if line.startswith("IP:"):
                    sv_ip = line.split(":", 1)[1].strip()
                elif line.startswith("PWD:"):
                    sv_pwd = line.split(":", 1)[1].strip()
            if sv_ip and sv_pwd:
                print(f"  Supervisor IP: {sv_ip}")
                print(f"  Supervisor password: {'*' * len(sv_pwd)}")
                return sv_ip, sv_pwd
        sv_ip = self._get_supervisor_ip_from_api()
        if sv_ip:
            raise RuntimeError(
                f"Found Supervisor IP {sv_ip} from vCenter but could not retrieve "
                "its password via decryptK8Pwd.py. "
                "Provide --supervisor-ip / --supervisor-password directly."
            )
        raise RuntimeError(
            "Could not retrieve Supervisor credentials from vCenter. "
            "Ensure WCP is enabled and "
            "/usr/lib/vmware-wcp/decryptK8Pwd.py is available."
        )

    def _get_supervisor_ip_from_api(self) -> str | None:
        _, stdout, _ = self.ssh.exec_command(
            "grep -r 'control-plane' /etc/vmware-wcp/ 2>/dev/null | head -1 || "
            "cat /etc/vmware-wcp/wcpsvc.yaml 2>/dev/null | grep -i 'address' | head -1"
        )
        output = stdout.read().decode().strip()
        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
        return m.group(1) if m else None

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_API_VERSION = "v1alpha6"
SUPPORTED_API_VERSIONS = ("v1alpha5", "v1alpha6")
POLL_INTERVAL = 5
# Max time to wait for VM to reach a terminal state (Created, Running, Failed, Unknown).
VM_TERMINAL_WAIT_TIMEOUT = 5 * 60  # 5 minutes
ARTIFACTS_BASE = _HACK_DIR / "artifacts"
SUCCESS_HISTORY_FILENAME = "fuzzer_success_history.json"

# Categories for Categorizer
CAT_VALIDATION = "VALIDATION"
CAT_PLACEMENT = "PLACEMENT"
CAT_POWER_ON = "POWER_ON"
CAT_GUEST_TIMEOUT = "GUEST_TIMEOUT"
CAT_INFRA = "INFRA"
CAT_UNKNOWN = "UNKNOWN"

# Annotation to disable Fast Deploy for a VM (use deployOVF/createVM path instead).
# Value must be anything other than "direct" or "linked" per vmoperator.vmware.com/fast-deploy.
FAST_DEPLOY_DISABLED_ANNOTATION = {"vmoperator.vmware.com/fast-deploy": "disabled"}

# -----------------------------------------------------------------------------
# TestRegistry: data-driven list of test cases
# -----------------------------------------------------------------------------
# Each entry: id, category (expected), description, vm_spec_override, class_spec_override (optional).
# class_spec_override: when set, a temporary VMClass is created for this test and the VM references it.
# vm_spec_override: merged into the VM spec (imageName, className, bootOptions, etc.).
INITIAL_PAYLOADS: list[dict[str, Any]] = [
    {
        "id": "invalid-pci-vgpu",
        "category": CAT_PLACEMENT,
        "description": "VMClass with non-existent vGPU profile",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {
                "cpus": 2,
                "memory": "4Gi",
                "devices": {
                    "vgpuDevices": [{"profileName": "non-existent-profile"}],
                },
            },
            "policies": {"resources": {}},
        },
    },
    {
        "id": "malformed-extraconfig",
        "category": CAT_POWER_ON,
        "description": "configSpec.extraConfig with invalid-bool for numa.autosize",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "extraConfig": [
                    {
                        "_typeName": "OptionValue",
                        "key": "numa.autosize",
                        "value": {"_typeName": "string", "_value": "invalid-bool"},
                    },
                ],
            },
        },
    },
    {
        "id": "firmware-uefi-mismatch",
        "category": CAT_POWER_ON,
        "description": "VM spec.bootOptions.firmware=efi (may conflict with image)",
        "vm_spec_override": {
            "bootOptions": {"firmware": "efi"},
        },
        "class_spec_override": None,
    },
    # -------------------------------------------------------------------------
    # ConfigSpec deviceChange with virtual device types (govmomi vim25/types)
    # -------------------------------------------------------------------------
    {
        "id": "vmclass-vgpu-invalid-profile",
        "category": CAT_PLACEMENT,
        "description": "VMClass first-class vgpuDevices with non-existent profile (was configSpec vGPU)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {
                "cpus": 2,
                "memory": "4Gi",
                "devices": {"vgpuDevices": [{"profileName": "non-existent-vgpu-profile"}]},
            },
            "policies": {"resources": {}},
        },
    },
    {
        "id": "vmclass-dynamic-pci-invalid",
        "category": CAT_PLACEMENT,
        "description": "VMClass first-class dynamicDirectPathIODevices with invalid vendorId/deviceId (was configSpec)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {
                "cpus": 2,
                "memory": "4Gi",
                "devices": {
                    "dynamicDirectPathIODevices": [
                        {"vendorID": 0, "deviceID": 0},
                    ],
                },
            },
            "policies": {"resources": {}},
        },
    },
    {
        "id": "configspec-disk-add-invalid",
        "category": CAT_POWER_ON,
        "description": "configSpec.deviceChange: add VirtualDisk with zero capacity (invalid)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 1,
                            "capacityInKB": 0,
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-nic-e1000",
        "category": CAT_POWER_ON,
        "description": "configSpec.deviceChange: add VirtualE1000 (extra NIC)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualE1000",
                            "key": -1,
                            "addressType": "Generated",
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-extraconfig-unknown",
        "category": CAT_POWER_ON,
        "description": "configSpec.extraConfig: unknown/invalid key",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "extraConfig": [
                    {
                        "_typeName": "OptionValue",
                        "key": "vmop.fuzzer.unknown.key",
                        "value": {"_typeName": "string", "_value": "test"},
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-extraconfig-huge",
        "category": CAT_POWER_ON,
        "description": "configSpec with large extraConfig (numa, sched, svga, etc.)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 32, "memory": "128Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 32,
                "memoryMB": 131072,
                "firmware": "efi",
                "extraConfig": [
                    {"_typeName": "OptionValue", "key": "numa.nodeAffinity", "value": {"_typeName": "string", "_value": "0"}},
                    {"_typeName": "OptionValue", "key": "numa.vcpu.preferHT", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "numa.autosize.vcpu.preferHT", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "numa.vcpu.maxPerVirtualNode", "value": {"_typeName": "string", "_value": "8"}},
                    {"_typeName": "OptionValue", "key": "sched.mem.pshare.enable", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "sched.cpu.min", "value": {"_typeName": "string", "_value": "0"}},
                    {"_typeName": "OptionValue", "key": "sched.cpu.shares", "value": {"_typeName": "string", "_value": "normal"}},
                    {"_typeName": "OptionValue", "key": "sched.mem.shares", "value": {"_typeName": "string", "_value": "normal"}},
                    {"_typeName": "OptionValue", "key": "mem.hostpref", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "mem.prealloc", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "svga.numDisplays", "value": {"_typeName": "string", "_value": "1"}},
                    {"_typeName": "OptionValue", "key": "svga.autodetect", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "vhv.enable", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "vhv.allow", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "isolation.tools.copy.disable", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "isolation.tools.paste.disable", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "isolation.tools.setGUIOptions.enable", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "mce.enable", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "hypervisor.cpuid.v0", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "cpuid.0.eax", "value": {"_typeName": "string", "_value": "0000:0000:0000:0000:0000:0000:0000:1011"}},
                    {"_typeName": "OptionValue", "key": "cpuid.0.ebx", "value": {"_typeName": "string", "_value": "0111:0101:0110:1110:0110:0101:0100:0111"}},
                    {"_typeName": "OptionValue", "key": "cpuid.0.ecx", "value": {"_typeName": "string", "_value": "0110:1100:0110:0101:0111:0100:0110:1110"}},
                    {"_typeName": "OptionValue", "key": "cpuid.0.edx", "value": {"_typeName": "string", "_value": "0100:1001:0110:0101:0110:1110:0110:1001"}},
                    {"_typeName": "OptionValue", "key": "vmci0.unrestricted", "value": {"_typeName": "string", "_value": "false"}},
                    {"_typeName": "OptionValue", "key": "ethernet0.virtualDev", "value": {"_typeName": "string", "_value": "e1000e"}},
                    {"_typeName": "OptionValue", "key": "guestOS.detailed.data", "value": {"_typeName": "string", "_value": "linux"}},
                    {"_typeName": "OptionValue", "key": "tools.upgrade.policy", "value": {"_typeName": "string", "_value": "manual"}},
                    {"_typeName": "OptionValue", "key": "powerType.powerOff", "value": {"_typeName": "string", "_value": "soft"}},
                    {"_typeName": "OptionValue", "key": "powerType.powerOn", "value": {"_typeName": "string", "_value": "soft"}},
                    {"_typeName": "OptionValue", "key": "powerType.suspend", "value": {"_typeName": "string", "_value": "soft"}},
                    {"_typeName": "OptionValue", "key": "replay.supported", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "softPowerOff", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "keyboard.virtualSync", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "msg.autoanswer", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "uuid.bios", "value": {"_typeName": "string", "_value": "56 4d 41 2a 00 00 00 00-00 00 00 00 00 00 00 00"}},
                    {"_typeName": "OptionValue", "key": "uuid.location", "value": {"_typeName": "string", "_value": "56 4d 41 2a 00 00 00 00-00 00 00 00 00 00 00 00"}},
                    {"_typeName": "OptionValue", "key": "migrate.hostLog", "value": {"_typeName": "string", "_value": ""}},
                    {"_typeName": "OptionValue", "key": "vmx.buildType", "value": {"_typeName": "string", "_value": "release"}},
                    {"_typeName": "OptionValue", "key": "cleanShutdown", "value": {"_typeName": "string", "_value": "TRUE"}},
                    {"_typeName": "OptionValue", "key": "tools.remindInstall", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "toolsInstallManager.lastInstallError", "value": {"_typeName": "string", "_value": ""}},
                    {"_typeName": "OptionValue", "key": "toolsInstallManager.updateCounter", "value": {"_typeName": "string", "_value": "0"}},
                    {"_typeName": "OptionValue", "key": "monitor.allow_legacy_APIC", "value": {"_typeName": "string", "_value": "FALSE"}},
                    {"_typeName": "OptionValue", "key": "vm.genid", "value": {"_typeName": "string", "_value": "-1"}},
                    {"_typeName": "OptionValue", "key": "vm.genidX", "value": {"_typeName": "string", "_value": "-1"}},
                    {"_typeName": "OptionValue", "key": "vmx.allowNested", "value": {"_typeName": "string", "_value": "TRUE"}},
                ],
            },
        },
    },
    # -------------------------------------------------------------------------
    # createVm.py-style: basic VM create (power state, guest ID)
    # -------------------------------------------------------------------------
    {
        "id": "vm-power-state-off",
        "category": CAT_POWER_ON,
        "description": "VM with powerState PoweredOff (createVm-style)",
        "vm_spec_override": {"powerState": "PoweredOff"},
        "class_spec_override": None,
    },
    {
        "id": "vm-guest-id-invalid",
        "category": CAT_VALIDATION,
        "description": "VM with invalid/unsupported guestID (createVm-style)",
        "vm_spec_override": {"guestID": "invalidGuestId"},
        "class_spec_override": None,
    },
    # -------------------------------------------------------------------------
    # createVmWithVDiskFormat.py-style: virtual disk format (thin/thick/eagerZeroed)
    # -------------------------------------------------------------------------
    {
        "id": "configspec-disk-flatver2-thin",
        "category": CAT_POWER_ON,
        "description": "configSpec: add VirtualDisk with FlatVer2 thin backing",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "fileOperation": "create",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 1,
                            "capacityInKB": 1048576,
                            "backing": {
                                "_typeName": "VirtualDiskFlatVer2BackingInfo",
                                "thinProvisioned": True,
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-disk-flatver2-thick",
        "category": CAT_POWER_ON,
        "description": "configSpec: add VirtualDisk with FlatVer2 thick backing",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "fileOperation": "create",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 1,
                            "capacityInKB": 1048576,
                            "backing": {
                                "_typeName": "VirtualDiskFlatVer2BackingInfo",
                                "thinProvisioned": False,
                                "eagerZeroed": False,
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-disk-flatver2-eagerzeroed",
        "category": CAT_POWER_ON,
        "description": "configSpec: add VirtualDisk with FlatVer2 eagerZeroedThick",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "fileOperation": "create",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 1,
                            "capacityInKB": 1048576,
                            "backing": {
                                "_typeName": "VirtualDiskFlatVer2BackingInfo",
                                "thinProvisioned": False,
                                "eagerZeroed": True,
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-disk-backing-invalid-mode",
        "category": CAT_POWER_ON,
        "description": "configSpec: add VirtualDisk with invalid diskMode (createVmWithVDiskFormat-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 1,
                            "capacityInKB": 1048576,
                            "backing": {
                                "_typeName": "VirtualDiskFlatVer2BackingInfo",
                                "diskMode": "InvalidDiskMode",
                            },
                        },
                    },
                ],
            },
        },
    },

    {
        "id": "configspec-cpu-hotadd",
        "category": CAT_POWER_ON,
        "description": "configSpec: cpuHotAddEnabled true (createVmHwTest-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "cpuHotAddEnabled": True,
            },
        },
    },
    {
        "id": "configspec-memory-hotadd",
        "category": CAT_POWER_ON,
        "description": "configSpec: memoryHotAddEnabled true (createVmHwTest-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "memoryHotAddEnabled": True,
            },
        },
    },
    {
        "id": "vmclass-cpu-memory-zero",
        "category": CAT_VALIDATION,
        "description": "VMClass first-class hardware.cpus 0, memory 0Gi (invalid, createVmHwTest-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 0, "memory": "0Gi"},
            "policies": {"resources": {}},
        },
    },
    {
        "id": "configspec-disk-unsupported-format",
        "category": CAT_POWER_ON,
        "description": "configSpec: VirtualDisk with unsupported virtualDiskFormat (createVmWithVDiskFormat-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "fileOperation": "create",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 1,
                            "capacityInKB": 1048576,
                            "virtualDiskFormat": "native_123",
                            "backing": {
                                "_typeName": "VirtualDiskFlatVer2BackingInfo",
                                "thinProvisioned": True,
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-version-invalid",
        "category": CAT_VALIDATION,
        "description": "configSpec: invalid hardware version vmx-0 (createVmHwTest-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "version": "vmx-0",
            },
        },
    },
    {
        "id": "vm-boot-options-network-ip6",
        "category": CAT_POWER_ON,
        "description": "VM first-class bootOptions.networkBootProtocol IP6 (reconfigureBootOption-style)",
        "vm_spec_override": {
            "bootOptions": {"networkBootProtocol": "IP6"},
        },
        "class_spec_override": None,
    },
    {
        "id": "configspec-nic-invalid-backing",
        "category": CAT_POWER_ON,
        "description": "configSpec: add NIC with invalid backing (invalidNetDeviceChangeClone-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualE1000",
                            "key": -1,
                            "addressType": "Generated",
                            "backing": {
                                "_typeName": "VirtualEthernetCardNetworkBackingInfo",
                                "network": "",
                                "deviceName": "",
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-cdrom-add-invalid",
        "category": CAT_POWER_ON,
        "description": "configSpec: add VirtualCdrom with invalid backing (cloneInvalidCdrom-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualCdrom",
                            "key": -1,
                            "controllerKey": 200,
                            "unitNumber": 0,
                            "backing": {
                                "_typeName": "VirtualCdromIsoBackingInfo",
                                "fileName": "",
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-disk-rdm-backing",
        "category": CAT_PLACEMENT,
        "description": "configSpec: add VirtualDisk with RDM backing (createRdmBackedDiskOnNfs-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 1,
                            "capacityInKB": 1048576,
                            "backing": {
                                "_typeName": "VirtualDiskRawDiskMappingVer1BackingInfo",
                                "compatibilityMode": "physicalMode",
                                "deviceName": "",
                                "lunUuid": "invalid-rdm-lun",
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-duplicate-disk-unit",
        "category": CAT_POWER_ON,
        "description": "configSpec: two disks with same controllerKey and unitNumber (reconfigureDuplicateDiskKey-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "fileOperation": "create",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 0,
                            "capacityInKB": 1048576,
                            "backing": {"_typeName": "VirtualDiskFlatVer2BackingInfo", "thinProvisioned": True},
                        },
                    },
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "fileOperation": "create",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -2,
                            "controllerKey": 1000,
                            "unitNumber": 0,
                            "capacityInKB": 1048576,
                            "backing": {"_typeName": "VirtualDiskFlatVer2BackingInfo", "thinProvisioned": True},
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-vnuma",
        "category": CAT_POWER_ON,
        "description": "configSpec: vNUMA extraConfig only (vnumaClone-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 4, "memory": "8Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 4,
                "memoryMB": 8192,
                "extraConfig": [
                    {"_typeName": "OptionValue", "key": "numa.nodeAffinity", "value": {"_typeName": "string", "_value": "0"}},
                    {"_typeName": "OptionValue", "key": "numa.autosize", "value": {"_typeName": "string", "_value": "true"}},
                    {"_typeName": "OptionValue", "key": "numa.vcpu.maxPerVirtualNode", "value": {"_typeName": "string", "_value": "4"}},
                ],
            },
        },
    },
    {
        "id": "configspec-latency-sensitivity",
        "category": CAT_POWER_ON,
        "description": "configSpec: latency sensitivity extraConfig (latencySensivity-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "extraConfig": [
                    {"_typeName": "OptionValue", "key": "latency.sensitivity", "value": {"_typeName": "string", "_value": "high"}},
                ],
            },
        },
    },
    {
        "id": "configspec-disk-sharing-multiwriter",
        "category": CAT_POWER_ON,
        "description": "configSpec: VirtualDisk with sharingMultiWriter (block-bus-sharing-style)",
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "fileOperation": "create",
                        "device": {
                            "_typeName": "VirtualDisk",
                            "key": -1,
                            "controllerKey": 1000,
                            "unitNumber": 1,
                            "capacityInKB": 1048576,
                            "backing": {
                                "_typeName": "VirtualDiskFlatVer2BackingInfo",
                                "thinProvisioned": False,
                                "diskMode": "independent_persistent",
                                "sharing": "sharingMultiWriter",
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "vm-name-too-long",
        "category": CAT_VALIDATION,
        "description": "VM metadata.name over 253 chars (vmname-style)",
        "vm_spec_override": {},
        "class_spec_override": None,
        "vm_name_override": "a" * 260,
    },
    # -------------------------------------------------------------------------
    # Placement: zone-level VM anti-affinity (single-zone failure)
    # -------------------------------------------------------------------------
    # How it works:
    #   1. An "anchor" prereq VM is created first with label fuzz-zone-role=anchor.
    #      vm-operator converts that K8s label into a vSphere TagSpec when calling
    #      folder.CreateVM (genConfigSpecTagSpecsFromVMLabels in affinity.go).
    #   2. Once the anchor VM is physically created in vSphere (VirtualMachineCreated=True),
    #      the test VM is submitted.
    #   3. The test VM carries a VmToVmGroupsAntiAffinity placement policy
    #      (RequiredDuringScheduling, topology: zone) matching the anchor label.
    #      PlaceVmsXCluster sees the anchor's tag in the only zone → no candidates.
    #   4. VirtualMachinePlacementReady=False is expected.
    #
    # In multi-zone setups this test will PASS (the blocked VM lands in another zone).
    {
        "id": "zone-anti-affinity-required",
        "category": CAT_PLACEMENT,
        "description": (
            "Required zone-level VM anti-affinity via VirtualMachineGroup: "
            "'anchor' VM and 'blocked' VM are submitted simultaneously so the VMG "
            "controller places both in a single PlaceVmsXCluster call. "
            "DRS sees anchor's TagSpec (fuzz-zone-role:anchor) and blocked's "
            "VmToVmGroupsAntiAffinity policy together — anchor occupies the only zone, "
            "leaving no viable zone for blocked. "
            "Expects VirtualMachinePlacementReady=False for the blocked VM in "
            "single-zone setups. "
            "NOTE: TagSpecs are placement hints, not actual vSphere tag operations. "
            "Anti-affinity only works when both VMs are in the same PlaceVmsXCluster "
            "request. Waiting for the anchor to be created first (VirtualMachineCreated=True) "
            "causes it to acquire a UniqueID, which makes the VMG controller exclude it "
            "from subsequent group placement calls — breaking the constraint."
        ),
        "vm_group": True,
        # prereq_no_wait=True: submit the anchor and immediately submit the blocked VM
        # without waiting for VirtualMachineCreated=True on the anchor.
        # Both VMs must have no UniqueID when the VMG controller first runs
        # reconcilePlacement so they are included in the same PlaceVmsXCluster call.
        # DO NOT set pin_prereq_to_first_zone: the topology.kubernetes.io/zone label
        # causes getVMForPlacement() to return nil for that VM (line 693 of VMG controller),
        # which excludes the anchor from the group placement call and breaks the constraint.
        "prereq_no_wait": True,
        "prereq_vm": {
            "metadata_override": {"labels": {"fuzz-zone-role": "anchor"}},
            "vm_spec_override": {},  # groupName injected automatically by run_single_test
        },
        # Test VM: has required zone anti-affinity against the anchor label.
        # spec.groupName is injected automatically by run_single_test when vm_group=True.
        "vm_spec_override": {
            "affinity": {
                "vmAntiAffinity": {
                    "requiredDuringSchedulingPreferredDuringExecution": [
                        {
                            "topologyKey": "topology.kubernetes.io/zone",
                            "labelSelector": {
                                "matchLabels": {"fuzz-zone-role": "anchor"},
                            },
                        },
                    ],
                },
            },
        },
        "vm_metadata_override": {"labels": {"fuzz-zone-role": "blocked"}},
        "class_spec_override": None,
    },
    # -------------------------------------------------------------------------
    # Placement: memory too large for any available host
    # -------------------------------------------------------------------------
    # hardware.memory uses a Kubernetes resource quantity. 1000000Gi ≈ 1 PiB —
    # no real host can satisfy this, so PlaceVmsXCluster must return no candidates.
    {
        "id": "vmclass-huge-memory-hardware",
        "category": CAT_PLACEMENT,
        "description": (
            "VMClass hardware.memory=1000000Gi (≈1 PiB) — no host can satisfy "
            "placement; expects VirtualMachinePlacementReady=False"
        ),
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "1000000Gi"},
            "policies": {"resources": {}},
        },
    },
    # =========================================================================
    # DevicesSupportedByHost scenarios
    # vmCompatTestFunctions.cpp::DevicesSupportedByHost (line 2399)
    #
    # Calls ConfigOptionValidate::DeviceSupported() per-device against the
    # host's ConfigOption.  If a device TYPE is absent from the host's
    # supported device option list (optTypes), DRS returns a hard error fault
    # during PlaceVmsXCluster with PlacementType=createAndPowerOn.
    # =========================================================================
    # -------------------------------------------------------------------------
    # DevicesSupportedByHost: VirtualNVDIMM (persistent memory / PMem)
    # -------------------------------------------------------------------------
    # Requires: ESX host with physical PMem DIMMs (NVDIMM-N / Intel Optane DCPMM).
    # VirtualNVDIMMController + VirtualNVDIMM are absent from the ConfigOption
    # optTypes on standard compute hosts → DevicesSupportedByHost raises a
    # NotSupported fault → DRS returns a faults entry.
    # VirtualNVDIMMController is deprecated as of vSphere 9.0 API; on 9.0+
    # this may surface as a CAT_VALIDATION admission error before placement.
    # Expected: VirtualMachinePlacementReady=False.
    # -------------------------------------------------------------------------
    {
        "id": "configspec-nvdimm-device",
        "category": CAT_PLACEMENT,
        "description": (
            "DevicesSupportedByHost: VirtualNVDIMMController + VirtualNVDIMM (PMem) in "
            "configSpec. ConfigOptionValidate::DeviceSupported fails because VirtualNVDIMM "
            "is absent from the host's ConfigOption optTypes on non-PMem hosts. "
            "Triggers NotSupported fault during PlaceVmsXCluster createAndPowerOn "
            "compat check (vmCompatTestFunctions.cpp::DevicesSupportedByHost). "
            "vSphere 9.0+ marks VirtualNVDIMMController deprecated; may surface as "
            "a validation fault there. "
            "Expected: VirtualMachinePlacementReady=False."
        ),
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualNVDIMMController",
                            "key": -300,
                            "busNumber": 0,
                        },
                    },
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "fileOperation": "create",
                        "device": {
                            "_typeName": "VirtualNVDIMM",
                            "key": -301,
                            "controllerKey": -300,
                            "unitNumber": 0,
                            "capacityInMB": 1024,
                            "backing": {
                                "_typeName": "VirtualNVDIMMBackingInfo",
                                "fileName": "",
                            },
                        },
                    },
                ],
            },
        },
    },
    # -------------------------------------------------------------------------
    # DevicesSupportedByHost: VirtualSriovEthernetCard (SR-IOV NIC passthrough)
    # -------------------------------------------------------------------------
    # Requires: Physical NIC with SR-IOV capability enabled in BIOS and ESX.
    # DevicesSupportedByHost skips backing checks for VirtualEthernetCard
    # subtypes (ignoreBackingCheck = IsA<VirtualEthernetCard>(device) in
    # ConfigOptionValidate::DeviceSupported), so omitting sriovBacking is fine —
    # the device TYPE check alone triggers the fault on non-SR-IOV hosts.
    # Expected: VirtualMachinePlacementReady=False if no SR-IOV NIC on hosts.
    # -------------------------------------------------------------------------
    {
        "id": "configspec-sriov-nic",
        "category": CAT_PLACEMENT,
        "description": (
            "DevicesSupportedByHost: VirtualSriovEthernetCard in configSpec. "
            "SR-IOV NIC type must appear in the host's ConfigOption optTypes; "
            "hosts without SR-IOV-capable physical NICs will not list it. "
            "Backing is deliberately omitted — ConfigOptionValidate::DeviceSupported "
            "skips backing checks for VirtualEthernetCard subtypes "
            "(vmCompatTestFunctions.cpp::DevicesSupportedByHost, ignoreBackingCheck). "
            "Expected: VirtualMachinePlacementReady=False on non-SR-IOV hosts."
        ),
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualSriovEthernetCard",
                            "key": -1,
                            "addressType": "Generated",
                            "wakeOnLanEnabled": False,
                        },
                    },
                ],
            },
        },
    },
    # -------------------------------------------------------------------------
    # DevicesSupportedByHost: VirtualTPM (virtual Trusted Platform Module)
    # -------------------------------------------------------------------------
    # Requires: vCenter Key Provider configured + ESX host with TPM 2.0 chip.
    # Without a Key Provider, vTPM add is rejected by the admission webhook or
    # by ESX with a NotSupported / InvalidDeviceSpec fault before placement.
    # When a Key Provider exists but the host ConfigOption does not list
    # VirtualTPM in its device option types, DevicesSupportedByHost blocks.
    # efi firmware is required alongside vTPM.
    # Expected: VirtualMachinePlacementReady=False or webhook ValidationError.
    # -------------------------------------------------------------------------
    {
        "id": "configspec-vtpm-device",
        "category": CAT_PLACEMENT,
        "description": (
            "DevicesSupportedByHost: VirtualTPM device in configSpec. "
            "vTPM requires a vCenter Key Provider configured and the destination "
            "ESX host to support TPM 2.0. Without a Key Provider the request is "
            "rejected (InvalidDeviceSpec / NotSupported fault). "
            "When a Key Provider exists but no host supports vTPM, "
            "ConfigOptionValidate::DeviceSupported blocks placement "
            "(vmCompatTestFunctions.cpp::DevicesSupportedByHost). "
            "EFI firmware is set alongside vTPM as required by the vSphere API. "
            "Expected: VirtualMachinePlacementReady=False (or admission webhook error)."
        ),
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "firmware": "efi",
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualTPM",
                            "key": -1,
                        },
                    },
                ],
            },
        },
    },
    # =========================================================================
    # DevicesSupportedByGuest scenario
    # vmCompatTestFunctions.cpp::DevicesSupportedByGuest (line 2539)
    #
    # IMPORTANT: This check is completely skipped for DRS:
    #   if (vmOp->GetTestOptions()->IsForDRS()) { return; }
    # Even in the non-DRS power-on path it only generates WARNINGS
    # (HandleBadDeviceType called with forceWarning=true), never hard errors.
    # Consequence: this check NEVER blocks PlaceVmsXCluster placement and
    # NEVER prevents actual power-on.  This scenario documents that behavior.
    # =========================================================================
    # guestID=winXPProGuest + VirtualNVMEController:
    # Windows XP has no NVMe driver; ConfigOptionValidate::VirtualDiskSupported
    # would warn about NVMe controller incompatibility with the guest. But since
    # DRS skips DevicesSupportedByGuest entirely, placement is unaffected.
    # Expected: Placement SUCCEEDS; VM may fail to boot for OS/image reasons
    # unrelated to compat checks (missing drivers, image mismatch, etc.).
    # -------------------------------------------------------------------------
    {
        "id": "configspec-nvme-old-win",
        "category": CAT_POWER_ON,
        "description": (
            "DevicesSupportedByGuest: VirtualNVMEController + guestID=winXPProGuest. "
            "Windows XP has no NVMe driver; ConfigOptionValidate::VirtualDiskSupported "
            "would flag the controller as incompatible with the guest OS. "
            "HOWEVER: DevicesSupportedByGuest is completely skipped for DRS — "
            "'if (vmOp->GetTestOptions()->IsForDRS()) { return; }' at line 2542 "
            "of vmCompatTestFunctions.cpp — and even in the non-DRS power-on path "
            "it only generates warnings (HandleBadDeviceType forceWarning=true), "
            "never hard errors. "
            "This scenario verifies that guest-device incompatibility NEVER blocks "
            "PlaceVmsXCluster (placement succeeds). "
            "Expected: Placement SUCCEEDS; VM may fail to power on for OS/image reasons."
        ),
        "vm_spec_override": {
            "guestID": "winXPProGuest",
        },
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "deviceChange": [
                    {
                        "_typeName": "VirtualDeviceConfigSpec",
                        "operation": "add",
                        "device": {
                            "_typeName": "VirtualNVMEController",
                            "key": -300,
                            "busNumber": 0,
                        },
                    },
                ],
            },
        },
    },
    # =========================================================================
    # GuestRequirementsSupportedByHost scenario
    # vmCompatTestFunctions.cpp::GuestRequirementsSupportedByHost (line 2594)
    #
    # Checks: osDescriptor->IsSmcRequired() && !destHwInfo->IsSmcPresent()
    # All darwin* (macOS) guestIds have IsSmcRequired()==true.
    # Standard x86 vSphere hosts have IsSmcPresent()==false.
    # For PlaceVmsXCluster createAndPowerOn: VM powerState is poweredOn →
    # UnsupportedGuest fault is added as a hard ERROR (not warning).
    #
    # Note: if darwin21_64Guest is absent from the host ConfigOption guest list,
    # GuestSupported() fails first with the same UnsupportedGuest fault —
    # net outcome is identical regardless of which sub-check fires.
    # =========================================================================
    {
        "id": "vm-guest-id-macos-smc",
        "category": CAT_PLACEMENT,
        "description": (
            "GuestRequirementsSupportedByHost: guestID=darwin21_64Guest (macOS Monterey). "
            "GuestRequirementsSupportedByHost checks osDescriptor->IsSmcRequired() "
            "(true for all darwin guestIds) against destHwInfo->IsSmcPresent() "
            "(false on standard x86 vSphere hardware). "
            "For PlaceVmsXCluster createAndPowerOn the VM state is poweredOn and "
            "forceWarning=false, so UnsupportedGuest is a hard error — not a warning. "
            "If darwin21_64Guest is absent from the host ConfigOption, GuestSupported() "
            "fires the same UnsupportedGuest fault one level up. "
            "Expected: VirtualMachinePlacementReady=False with UnsupportedGuest."
        ),
        "vm_spec_override": {
            "guestID": "darwin21_64Guest",
        },
        "class_spec_override": None,
    },
    # =========================================================================
    # DatastoreSupported scenario
    # vmCompatTestFunctions.cpp::DatastoreSupported (line 2788)
    #
    # Checks each destination datastore against
    # destVmConfigOption->GetDatastore()->GetUnsupportedVolumes() for the
    # VM's hardware version.  Three trigger paths:
    #
    # 1. VMFS3 EOL: host capability vmfs3EOLSupported=true + VMFS 3 datastore
    #    → UnsupportedDatastore fault (rare: VMFS 3 essentially retired).
    #
    # 2. NAS filesystem type: unsupportedVolumes for the vmx version lists
    #    NFS or NFS41 as unsupported.  Very old vmx versions (vmx-4) predate
    #    NFS 4.1; their ConfigOption entry may list NFS41 as unsupported. If
    #    the storage policy resolves to an NFS 4.1 datastore the fault fires.
    #
    # 3. VVol disk descriptor version: VirtualDiskVersionSupported() checks
    #    disk.version vs host.maxVirtualDiskDescVersionSupported. Determined
    #    by backing on the datastore — not settable from configSpec alone.
    #
    # This scenario uses version=vmx-4. On modern ESX hosts
    # VirtualHardwareVersionSupported will likely fail first (vmx-4 < host
    # minimum).  DatastoreSupported fires independently only if vmx-4 IS a
    # recognized version but the environment uses NFS 4.1 or VVol storage.
    # =========================================================================
    {
        "id": "configspec-old-hwversion-datastore",
        "category": CAT_PLACEMENT,
        "description": (
            "DatastoreSupported: configSpec.version=vmx-4 (VMware Workstation 4 era). "
            "DatastoreSupported checks the host ConfigOption unsupportedVolumes list "
            "for the VM's hardware version against the placement datastores. "
            "vmx-4's ConfigOption on modern ESX may list NFS41 as unsupported; if "
            "the storage policy resolves to an NFS 4.1 datastore, UnsupportedDatastore "
            "fault is raised during PlaceVmsXCluster "
            "(vmCompatTestFunctions.cpp::DatastoreSupported, line 2788). "
            "On most modern hosts VirtualHardwareVersionSupported fails first "
            "(vmx-4 below the host minimum supported version). "
            "DatastoreSupported fires independently only when vmx-4 is recognized "
            "but carries NFS/VVol datastore restrictions (environment-dependent). "
            "Expected: VirtualMachinePlacementReady=False "
            "(VirtualHardwareVersionSupported or DatastoreSupported UnsupportedDatastore)."
        ),
        "vm_spec_override": {},
        "class_spec_override": {
            "hardware": {"cpus": 2, "memory": "4Gi"},
            "policies": {"resources": {}},
            "configSpec": {
                "_typeName": "VirtualMachineConfigSpec",
                "numCPUs": 2,
                "memoryMB": 4096,
                "version": "vmx-4",
            },
        },
    },
]


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins; lists are replaced."""
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# -----------------------------------------------------------------------------
# ManifestFactory: v1alpha5 / v1alpha6 VM and VMClass YAML
# -----------------------------------------------------------------------------
# configSpec follows VirtualMachineConfigSpec schema (see docs/concepts/workloads/vm-class.md):
#   _typeName: VirtualMachineConfigSpec
#   numCPUs, memoryMB, firmware, extraConfig (OptionValue list), deviceChange, etc.
class ManifestFactory:
    """Builds VM and optional VMClass manifests for a given API version."""

    def __init__(self, api_version: str) -> None:
        if api_version not in SUPPORTED_API_VERSIONS:
            raise ValueError(f"api_version must be one of {SUPPORTED_API_VERSIONS}")
        self.api_version = api_version
        self.api_group = "vmoperator.vmware.com"
        self.api_prefix = f"{self.api_group}/{api_version}"

    def vm_manifest(
        self,
        name: str,
        namespace: str,
        image_name: str,
        class_name: str,
        vm_spec_override: dict[str, Any],
        storage_class: str = "wcpglobal-storage-profile-latebinding",
        power_state: str = "PoweredOn",
        guest_id: str = "vmwarePhoton64Guest",
        vm_metadata_override: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        base_spec: dict[str, Any] = {
            "imageName": image_name,
            "className": class_name,
            "storageClass": storage_class,
            "powerState": power_state,
            "guestID": guest_id,
        }
        spec = _deep_merge(base_spec, vm_spec_override)
        metadata: dict[str, Any] = {"name": name, "namespace": namespace}
        if vm_metadata_override:
            metadata = _deep_merge(metadata, vm_metadata_override)
        return {
            "apiVersion": self.api_prefix,
            "kind": "VirtualMachine",
            "metadata": metadata,
            "spec": spec,
        }

    @staticmethod
    def build_config_spec(
        num_cpus: int = 0,
        memory_mb: int = 0,
        extra_config: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Build a VirtualMachineConfigSpec dict per vm-class.md schema.
        extra_config: list of {"key": str, "value": str}; values are emitted as
        OptionValue with _typeName: string and _value.
        """
        spec: dict[str, Any] = {"_typeName": "VirtualMachineConfigSpec"}
        if num_cpus > 0:
            spec["numCPUs"] = num_cpus
        if memory_mb > 0:
            spec["memoryMB"] = memory_mb
        if extra_config:
            spec["extraConfig"] = [
                {
                    "_typeName": "OptionValue",
                    "key": entry.get("key", ""),
                    "value": {
                        "_typeName": "string",
                        "_value": str(entry.get("value", "")),
                    },
                }
                for entry in extra_config
            ]
        for k, v in kwargs.items():
            if v is not None:
                spec[k] = v
        return spec

    @staticmethod
    def normalize_config_spec(raw: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize a configSpec dict to the VirtualMachineConfigSpec schema.
        Ensures _typeName and converts simple extraConfig [{key, value}] to OptionValue form.
        """
        out = dict(raw)
        if "_typeName" not in out:
            out["_typeName"] = "VirtualMachineConfigSpec"
        ec = out.get("extraConfig")
        if ec and isinstance(ec, list):
            normalized = []
            for entry in ec:
                if isinstance(entry, dict) and "_typeName" not in entry:
                    normalized.append({
                        "_typeName": "OptionValue",
                        "key": entry.get("key", ""),
                        "value": {
                            "_typeName": "string",
                            "_value": str(entry.get("value", "")),
                        },
                    })
                else:
                    normalized.append(entry)
            out["extraConfig"] = normalized
        return out

    def vmclass_manifest(
        self,
        name: str,
        namespace: str,
        class_spec: dict[str, Any],
    ) -> dict[str, Any]:
        spec = dict(class_spec)
        if "configSpec" in spec and isinstance(spec["configSpec"], dict):
            spec["configSpec"] = self.normalize_config_spec(spec["configSpec"])
        return {
            "apiVersion": self.api_prefix,
            "kind": "VirtualMachineClass",
            "metadata": {"name": name, "namespace": namespace},
            "spec": spec,
        }

    def vmgroup_manifest(
        self,
        name: str,
        namespace: str,
        member_names: list[str],
        member_kind: str = "VirtualMachine",
    ) -> dict[str, Any]:
        """Build a VirtualMachineGroup manifest.

        All members are placed in one BootOrder entry (no power-on delay).
        The group controller uses spec.bootOrder[].members as the authoritative
        member list for both reconciliation and placement; VMs must appear here
        AND carry spec.groupName pointing at this group.
        """
        members = [{"name": m, "kind": member_kind} for m in member_names]
        return {
            "apiVersion": self.api_prefix,
            "kind": "VirtualMachineGroup",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "bootOrder": [{"members": members}],
            },
        }


# -----------------------------------------------------------------------------
# Categorizer: map K8s condition Reasons to category
# -----------------------------------------------------------------------------
REASON_TO_CATEGORY: dict[str, str] = {
    # Validation / webhook
    "HardwareControllersMismatch": CAT_VALIDATION,
    "HardwareVolumesMismatch": CAT_VALIDATION,
    "HardwareCDROMMismatch": CAT_VALIDATION,
    "HardwareDeviceConfigMismatch": CAT_VALIDATION,
    "VirtualMachineClassReady": CAT_VALIDATION,
    "VirtualMachineImageReady": CAT_VALIDATION,
    "VirtualMachineBootstrapReady": CAT_VALIDATION,
    "VirtualMachineNetworkReady": CAT_VALIDATION,
    "VirtualMachineStorageReady": CAT_VALIDATION,
    # Placement
    "VirtualMachinePlacementReady": CAT_PLACEMENT,
    "VirtualMachinePlacementFailed": CAT_PLACEMENT,
    "Placement": CAT_PLACEMENT,
    # Power-on / create
    "VirtualMachineCreated": CAT_POWER_ON,
    "CreateError": CAT_POWER_ON,
    "PowerOn": CAT_POWER_ON,
    "PowerOnFailed": CAT_POWER_ON,
    # Guest customization / timeout
    "GuestCustomizationFailed": CAT_GUEST_TIMEOUT,
    "GuestCustomizationPending": CAT_GUEST_TIMEOUT,
    "GuestCustomizationRunning": CAT_GUEST_TIMEOUT,
    "GuestCustomizationIdle": CAT_GUEST_TIMEOUT,
    "GuestBootstrap": CAT_GUEST_TIMEOUT,
    "VirtualMachineToolsNotRunning": CAT_GUEST_TIMEOUT,
    # Infra / other
    "VirtualMachineReconcileReady": CAT_INFRA,
    "VirtualMachineReconcileRunning": CAT_INFRA,
    "VirtualMachineReconcilePaused": CAT_INFRA,
}


def categorize_reasons(conditions: list[dict], events: list[dict]) -> str:
    """Map condition reasons and event reasons to a single category (first match)."""
    reasons: set[str] = set()
    for c in conditions:
        r = (c.get("reason") or "").strip()
        if r:
            reasons.add(r)
    for e in events:
        r = (e.get("reason") or "").strip()
        if r:
            reasons.add(r)
    for r in reasons:
        if r in REASON_TO_CATEGORY:
            return REASON_TO_CATEGORY[r]
    return CAT_UNKNOWN


# -----------------------------------------------------------------------------
# vCenter task capture (during VM wait)
# -----------------------------------------------------------------------------
def _task_info_to_dict(info: Any, obj_ref: Any = None) -> dict[str, Any]:
    """Build a JSON-serializable dict from a TaskInfo object."""
    start_time = getattr(info, "startTime", None)
    start_ts = start_time if (start_time is not None and hasattr(start_time, "isoformat")) else None
    complete_time = getattr(info, "completeTime", None)
    err = getattr(info, "error", None)
    err_str = getattr(err, "msg", None) or str(err) if err is not None else ""
    desc = getattr(info, "description", None)
    desc_msg = getattr(desc, "message", "") or "" if (desc is not None and hasattr(desc, "message")) else ""
    start_str = start_ts.isoformat() if (start_ts is not None and hasattr(start_ts, "isoformat")) else (str(start_ts) if start_ts else "")
    complete_str = complete_time.isoformat() if (complete_time is not None and hasattr(complete_time, "isoformat")) else (str(complete_time) if complete_time else "")
    return {
        "key": str(obj_ref) if obj_ref is not None else "",
        "name": getattr(info, "name", "") or "",
        "state": getattr(info, "state", "") or "",
        "startTime": start_str,
        "completeTime": complete_str,
        "entityName": getattr(info, "entityName", "") or "",
        "error": err_str,
        "description": desc_msg,
    }


def get_vcenter_tasks(
    service_instance: Any,
    since_timestamp: float,
    entity_name: str | None = None,
) -> list[dict[str, Any]]:
    """Query vCenter TaskManager for recent tasks. No time-based filtering.
    When entity_name is set, only tasks whose entityName matches are returned; otherwise all recent tasks.
    Uses TraversalSpec from TaskManager.recentTask first, then falls back to iterating recentTask.
    """
    try:
        from pyVmomi import vim
    except ImportError:
        return []
    if not service_instance:
        return []
    out: list[dict[str, Any]] = []

    def add_task_info(info: Any, obj_ref: Any) -> None:
        # Name-based filter only: include only when entity_name is unset or matches
        if entity_name:
            task_entity = getattr(info, "entityName", "") or ""
            if task_entity != entity_name:
                return
        out.append(_task_info_to_dict(info, obj_ref))

    try:
        content = service_instance.RetrieveContent()
        task_manager = content.taskManager
        pc = content.propertyCollector

        # Method 1: TraversalSpec from TaskManager.recentTask
        try:
            traversal = vim.PropertyCollector.TraversalSpec()
            traversal.name = "recentTask"
            traversal.path = "recentTask"
            traversal.skip = False
            traversal.type = vim.TaskManager

            obj_spec = vim.PropertyCollector.ObjectSpec()
            obj_spec.obj = task_manager
            obj_spec.skip = False
            obj_spec.selectSet = [traversal]

            prop_spec = vim.PropertyCollector.PropertySpec()
            prop_spec.type = vim.Task
            prop_spec.pathSet = ["info"]

            filter_spec = vim.PropertyCollector.FilterSpec()
            filter_spec.objectSet = [obj_spec]
            filter_spec.propSet = [prop_spec]

            result = pc.RetrieveContents([filter_spec])
            for obj_content in result:
                obj_ref = getattr(obj_content, "obj", None)
                for prop in getattr(obj_content, "propSet", []) or []:
                    if getattr(prop, "name", "") != "info":
                        continue
                    info = getattr(prop, "val", None)
                    if not info:
                        continue
                    add_task_info(info, obj_ref)
                if not (getattr(obj_content, "propSet", []) or []):
                    for prop in getattr(obj_content, "propset", []) or []:
                        if getattr(prop, "name", "") != "info":
                            continue
                        info = getattr(prop, "val", None)
                        if not info:
                            continue
                        add_task_info(info, obj_ref)
        except Exception:
            pass

        # Method 2: iterate recentTask and read task.info directly (fallback)
        if not out:
            recent = getattr(task_manager, "recentTask", None) or []
            for task in recent:
                try:
                    info = getattr(task, "info", None)
                    if not info:
                        continue
                    add_task_info(info, task)
                except Exception:
                    continue
    except Exception:
        pass
    return out


# -----------------------------------------------------------------------------
# KubeRunner: apply, watch, capture status/events, delete
# -----------------------------------------------------------------------------
@dataclass
class RunResult:
    test_id: str
    vm_name: str
    class_name: str | None
    success: bool  # True if we reached terminal state and captured data
    phase: str = ""
    conditions: list[dict] = field(default_factory=list)
    conditions_text: str = ""
    events: list[dict] = field(default_factory=list)
    events_text: str = ""
    observed_category: str = ""
    error_message: str = ""
    vm_manifest: dict = field(default_factory=dict)
    class_manifest: dict | None = None
    config_spec_validation: dict | None = None  # Result from ConfigSpecValidator when used
    vcenter_tasks: list[dict] = field(default_factory=list)  # vCenter tasks captured during wait


# Zone topology label key (same as corev1.LabelTopologyZone in Go)
_LABEL_TOPOLOGY_ZONE = "topology.kubernetes.io/zone"


@dataclass
class ZoneInfo:
    """Zone topology information from a Zone (namespaced) or AvailabilityZone (cluster-scoped) CR.

    Zone CR (FSS_WCP_WORKLOAD_DOMAIN_ISOLATION enabled):
      spec.managedVMs.poolMoIDs  — ResourcePool MoIDs for VMs in this zone/namespace
      spec.managedVMs.folderMoID — Folder MoID for VMs in this zone/namespace
      spec.availabilityZoneReference — parent cluster-scoped AZ name

    AvailabilityZone CR (legacy, cluster-scoped):
      spec.namespaces[ns].poolMoIDs / poolMoId — ResourcePool MoID(s)
      spec.namespaces[ns].folderMoId            — Folder MoID
      spec.clusterComputeResourceMoIDs          — CCR MoIDs
    """
    name: str
    cr_type: str                          # "Zone" or "AvailabilityZone"
    pool_mo_ids: list[str] = field(default_factory=list)
    folder_mo_id: str = ""
    cluster_mo_ids: list[str] = field(default_factory=list)
    spec: dict = field(default_factory=dict)
    status: dict = field(default_factory=dict)


class KubeRunner:
    """Apply/Watch/Delete VM (and optional VMClass); capture status.conditions and events."""

    def __init__(self, supervisor_client: Any) -> None:
        self.supervisor = supervisor_client

    def apply_manifest(self, manifest: dict) -> None:
        """Apply a single manifest (VM or VMClass) via kubectl.

        Uses the same SSH reconnect pattern as SupervisorClient.run_kubectl()
        so that a dropped SSH connection is transparently recovered from.
        """
        yaml_content = yaml.dump(manifest, default_flow_style=False, sort_keys=False)
        cmd = f"cat <<'VMEOF' | kubectl apply -f -\n{yaml_content}\nVMEOF"
        exit_code = 1
        err = ""
        for attempt in range(2):
            try:
                stdin, stdout, stderr = self.supervisor.ssh.exec_command(cmd)
                exit_code = stdout.channel.recv_exit_status()
                err = stderr.read().decode()
                break
            except (EOFError, OSError) as e:
                if attempt == 0 and hasattr(self.supervisor, "_open_ssh"):
                    print(f"  SSH connection lost ({e}), reconnecting...")
                    self.supervisor._open_ssh()
                else:
                    raise RuntimeError(f"SSH connection failed after reconnect: {e}") from e
        if exit_code != 0:
            raise RuntimeError(f"kubectl apply failed: {err}")

    def get_vm(self, namespace: str, vm_name: str) -> dict | None:
        """Return VM as dict or None if not found."""
        out, _, rc = self.supervisor.run_kubectl(
            f"get vm -n {namespace} {vm_name} -o json",
            check=False,
        )
        if rc != 0 or not out:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return None

    def get_events(self, namespace: str, name: str, kind: str = "VirtualMachine") -> list[dict]:
        """Return events for the resource (involvedObject)."""
        out, _, rc = self.supervisor.run_kubectl(
            f"get events -n {namespace} --field-selector involvedObject.name={name},involvedObject.kind={kind} -o json",
            check=False,
        )
        if rc != 0 or not out:
            return []
        try:
            data = json.loads(out)
            return data.get("items", [])
        except json.JSONDecodeError:
            return []

    def delete_vm(self, namespace: str, vm_name: str) -> None:
        self.supervisor.run_kubectl(
            f"delete vm -n {namespace} {vm_name} --ignore-not-found --wait=false",
            check=False,
        )

    def delete_vmclass(self, namespace: str, class_name: str) -> None:
        self.supervisor.run_kubectl(
            f"delete vmclass -n {namespace} {class_name} --ignore-not-found --wait=false",
            check=False,
        )

    def delete_vmgroup(self, namespace: str, group_name: str) -> None:
        self.supervisor.run_kubectl(
            f"delete vmg -n {namespace} {group_name} --ignore-not-found --wait=false",
            check=False,
        )

    def discover_zones(self, namespace: str) -> list[ZoneInfo]:
        """Discover available zones from Zone (WDI) or AvailabilityZone CRs.

        Tries namespaced Zone CRs first (FSS_WCP_WORKLOAD_DOMAIN_ISOLATION enabled);
        falls back to cluster-scoped AvailabilityZone CRs.  Returns an empty list
        when neither resource type is available or parseable.

        Zone CR fields used:
          spec.managedVMs.poolMoIDs  — RP MoIDs for VM workloads in this zone/ns
          spec.managedVMs.folderMoID — Folder MoID for VM workloads
          spec.availabilityZoneReference.name — parent AZ name

        AvailabilityZone CR fields used (per namespace):
          spec.namespaces[ns].poolMoIDs / poolMoId  — RP MoID(s)
          spec.namespaces[ns].folderMoId             — Folder MoID
          spec.clusterComputeResourceMoIDs           — CCR MoIDs
        """
        # --- Namespaced Zone CRs (WorkloadDomainIsolation) ---
        out, _, rc = self.supervisor.run_kubectl(
            f"get zone -n {namespace} -o json",
            check=False,
        )
        if rc == 0 and out:
            try:
                data = json.loads(out)
                zones: list[ZoneInfo] = []
                for item in data.get("items", []):
                    spec = item.get("spec", {})
                    managed_vms = spec.get("managedVMs", {})
                    zones.append(ZoneInfo(
                        name=item["metadata"]["name"],
                        cr_type="Zone",
                        pool_mo_ids=managed_vms.get("poolMoIDs", []),
                        folder_mo_id=managed_vms.get("folderMoID", ""),
                        cluster_mo_ids=[],
                        spec=spec,
                        status=item.get("status", {}),
                    ))
                if zones:
                    return zones
            except (json.JSONDecodeError, KeyError):
                pass

        # --- Cluster-scoped AvailabilityZone CRs (legacy) ---
        out, _, rc = self.supervisor.run_kubectl(
            "get availabilityzone -o json",
            check=False,
        )
        if rc == 0 and out:
            try:
                data = json.loads(out)
                zones = []
                for item in data.get("items", []):
                    spec = item.get("spec", {})
                    ns_info = spec.get("namespaces", {}).get(namespace, {})
                    pool_mo_ids = ns_info.get("poolMoIDs", [])
                    if not pool_mo_ids and ns_info.get("poolMoId"):
                        pool_mo_ids = [ns_info["poolMoId"]]
                    cluster_mo_ids = spec.get("clusterComputeResourceMoIDs", [])
                    if not cluster_mo_ids and spec.get("clusterComputeResourceMoId"):
                        cluster_mo_ids = [spec["clusterComputeResourceMoId"]]
                    zones.append(ZoneInfo(
                        name=item["metadata"]["name"],
                        cr_type="AvailabilityZone",
                        pool_mo_ids=pool_mo_ids,
                        folder_mo_id=ns_info.get("folderMoId", ""),
                        cluster_mo_ids=cluster_mo_ids,
                        spec=spec,
                        status=item.get("status", {}),
                    ))
                if zones:
                    return zones
            except (json.JSONDecodeError, KeyError):
                pass

        return []

    def wait_until_terminal(
        self,
        namespace: str,
        vm_name: str,
        timeout: int = VM_TERMINAL_WAIT_TIMEOUT,
        vc_si: Any = None,
        vcenter_tasks_out: list[dict] | None = None,
    ) -> tuple[bool, str]:
        """Poll VM until all condition.status are True, or timeout after 5 min. Returns (reached, last_reason).
        Success only when every condition has status True; otherwise keep polling until deadline.
        """
        deadline_secs = min(timeout, VM_TERMINAL_WAIT_TIMEOUT)
        start = time.time()
        last_reason = ""
        seen_task_keys: set[str] = set()
        while time.time() - start < deadline_secs:
            # Capture vCenter tasks during wait (if vc_si and list provided)
            if vc_si and vcenter_tasks_out is not None:
                for t in get_vcenter_tasks(vc_si, start, entity_name=vm_name):
                    key = t.get("key", "")
                    if key and key not in seen_task_keys:
                        seen_task_keys.add(key)
                        vcenter_tasks_out.append(t)
            vm = self.get_vm(namespace, vm_name)
            if vm:
                status = vm.get("status", {})
                conditions = status.get("conditions", [])
                if not conditions:
                    time.sleep(POLL_INTERVAL)
                    continue
                # Success only when all conditions have status True
                all_true = all(c.get("status") == "True" for c in conditions)
                if all_true:
                    return True, "All conditions True"
                # Keep last failure reason for timeout message
                for c in conditions:
                    if c.get("status") == "False":
                        last_reason = c.get("reason") or c.get("message", "")
                        break
            time.sleep(POLL_INTERVAL)
        return False, last_reason or "timeout"


# -----------------------------------------------------------------------------
# ConfigSpecValidator: verify configSpec was applied via pyVmomi
# -----------------------------------------------------------------------------
def _option_value_to_str(opt: Any) -> str:
    """Convert pyVmomi OptionValue.value or similar to string for comparison."""
    if opt is None:
        return ""
    if hasattr(opt, "_value"):
        return str(getattr(opt, "_value", opt))
    if hasattr(opt, "value"):
        v = getattr(opt, "value", None)
        if hasattr(v, "_value"):
            return str(getattr(v, "_value", v))
        return str(v) if v is not None else ""
    return str(opt)


def _extra_config_to_dict(extra_config: list[Any] | None) -> dict[str, str]:
    """Convert list of OptionValue (pyVmomi or dict with key/value) to key -> value dict."""
    out: dict[str, str] = {}
    if not extra_config:
        return out
    for item in extra_config:
        if isinstance(item, dict):
            key = item.get("key", "")
            val = item.get("value")
            if isinstance(val, dict) and "_value" in val:
                out[key] = str(val["_value"])
            else:
                out[key] = str(val) if val is not None else ""
        else:
            key = getattr(item, "key", "")
            out[key] = _option_value_to_str(getattr(item, "value", None))
    return out


class ConfigSpecValidator:
    """
    Validates that a VM's vSphere configuration matches the expected configSpec
    using pyVmomi (SOAP API). Use when a VM was created with a VMClass configSpec
    to verify the backend applied it.
    """

    def __init__(self, service_instance: Any) -> None:
        """
        Args:
            service_instance: pyVmomi ServiceInstance (e.g. from VCenterClient.si).
        """
        self.si = service_instance

    def _get_vm_by_name(self, vm_name: str) -> Any | None:
        """Find a VM in the inventory by name. Returns the VM object or None."""
        try:
            from pyVmomi import vim
        except ImportError as e:
            raise RuntimeError("pyVmomi is required for ConfigSpec validation. pip install pyvmomi") from e
        content = self.si.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )
        try:
            for vm in container.view:
                if vm.name == vm_name:
                    return vm
        finally:
            container.Destroy()
        return None

    def validate(self, vm_name: str, expected_config_spec: dict[str, Any]) -> dict[str, Any]:
        """
        Compare the VM's actual config (numCPUs, memoryMB, extraConfig) with the
        expected configSpec. Returns a JSON-serializable result dict with:
          applied: bool
          message: str
          mismatches: list[str]
          expected: dict (snapshot of what we expected)
          actual: dict (snapshot of what we read from the VM)
        """
        try:
            from pyVmomi import vim
        except ImportError as e:
            raise RuntimeError("pyVmomi is required for ConfigSpec validation. pip install pyvmomi") from e

        result: dict[str, Any] = {
            "applied": False,
            "message": "",
            "mismatches": [],
            "expected": {},
            "actual": {},
        }
        vm = self._get_vm_by_name(vm_name)
        if not vm:
            result["message"] = f"VM '{vm_name}' not found in vCenter"
            return result

        config = vm.config
        if not config:
            result["message"] = "VM has no config (invalid or not yet created)"
            return result

        expected = result["expected"]
        actual = result["actual"]
        mismatches = result["mismatches"]

        # numCPUs
        want_cpus = expected_config_spec.get("numCPUs")
        if want_cpus is not None:
            expected["numCPUs"] = want_cpus
            got_cpus = getattr(config.hardware, "numCPU", None)
            actual["numCPUs"] = got_cpus
            if got_cpus != want_cpus:
                mismatches.append(f"numCPUs: expected {want_cpus}, got {got_cpus}")

        # memoryMB
        want_mb = expected_config_spec.get("memoryMB")
        if want_mb is not None:
            expected["memoryMB"] = want_mb
            got_mb = getattr(config.hardware, "memoryMB", None)
            actual["memoryMB"] = got_mb
            if got_mb != want_mb:
                mismatches.append(f"memoryMB: expected {want_mb}, got {got_mb}")

        # extraConfig: compare key/value
        want_extra = expected_config_spec.get("extraConfig")
        if want_extra is not None:
            want_extra_dict: dict[str, str] = {}
            for entry in want_extra:
                if isinstance(entry, dict):
                    key = entry.get("key", "")
                    val = entry.get("value")
                    if isinstance(val, dict) and "_value" in val:
                        want_extra_dict[key] = str(val["_value"])
                    else:
                        want_extra_dict[key] = str(val) if val is not None else ""
                else:
                    key = getattr(entry, "key", "")
                    want_extra_dict[key] = _option_value_to_str(getattr(entry, "value", None))
            expected["extraConfig"] = want_extra_dict
            raw_extra = getattr(config, "extraConfig", None) or []
            actual["extraConfig"] = _extra_config_to_dict(raw_extra)
            for k, v in want_extra_dict.items():
                if k not in actual["extraConfig"]:
                    mismatches.append(f"extraConfig['{k}']: expected '{v}', missing on VM")
                elif actual["extraConfig"][k] != v:
                    mismatches.append(
                        f"extraConfig['{k}']: expected '{v}', got '{actual['extraConfig'][k]}'"
                    )

        # deviceChange: record add count and actual device count (exact match is hard)
        want_devices = expected_config_spec.get("deviceChange")
        if want_devices is not None:
            add_ops = [
                d for d in want_devices
                if isinstance(d, dict) and d.get("operation") == "add"
            ]
            expected["deviceChange_add_count"] = len(add_ops)
            raw_devices = getattr(config.hardware, "device", None) or []
            actual["device_count"] = len(raw_devices)

        result["applied"] = len(mismatches) == 0
        result["message"] = "ConfigSpec applied" if result["applied"] else "; ".join(mismatches)
        return result


_PREREQ_VM_CREATED_TIMEOUT = 120  # seconds to wait for prereq VM to be created in vSphere


def _wait_for_prereq_vm(runner: KubeRunner, namespace: str, vm_name: str) -> bool:
    """
    Wait for a prerequisite VM to be Created in vSphere (VirtualMachineCreated=True).

    VM labels become vSphere tags only after the VM is physically created via
    folder.CreateVM (see genConfigSpecTagSpecsFromVMLabels). The anti-affinity
    placement policy for the *test* VM evaluates against those tags, so we must
    wait here before submitting the test VM.

    Returns True when the condition is observed, False on timeout.
    """
    start = time.time()
    while time.time() - start < _PREREQ_VM_CREATED_TIMEOUT:
        vm = runner.get_vm(namespace, vm_name)
        if vm:
            for cond in vm.get("status", {}).get("conditions", []):
                if cond.get("type") == "VirtualMachineCreated" and cond.get("status") == "True":
                    return True
        time.sleep(POLL_INTERVAL)
    return False


def run_single_test(
    runner: KubeRunner,
    factory: ManifestFactory,
    namespace: str,
    image_name: str,
    base_class_name: str,
    storage_class: str,
    test_entry: dict[str, Any],
    artifacts_dir: Path,
    timeout: int = VM_TERMINAL_WAIT_TIMEOUT,
    keep_vm: bool = False,
    vc_si: Any = None,
    zones: list[ZoneInfo] | None = None,
) -> RunResult:
    """Run one test from the registry: create VM (and optional class), wait, capture, cleanup (with manifest save). If keep_vm True, VM and VMClass are not deleted."""
    test_id = test_entry["id"]
    vm_name = test_entry.get("vm_name_override") or f"fuzz-{test_id}-{uuid.uuid4().hex[:8]}"
    vm_spec_override = dict(test_entry.get("vm_spec_override") or {})
    class_spec_override = test_entry.get("class_spec_override")
    created_class_name: str | None = None

    # Optional prerequisite VM — created before the test VM and deleted after.
    prereq_vm_def: dict[str, Any] | None = test_entry.get("prereq_vm")
    prereq_vm_name: str | None = None

    # VirtualMachineGroup support.
    # The admission webhook enforces: spec.affinity requires spec.groupName != "".
    # When vm_group=True the fuzzer creates a VMG CR listing both VMs, then injects
    # spec.groupName into each VM's spec so both are linked to the group.
    # The group controller drives placement for all members together, which allows
    # DRS to evaluate the inter-VM anti-affinity constraint across the group.
    use_vm_group = bool(test_entry.get("vm_group"))
    created_group_name: str | None = None

    if use_vm_group:
        created_group_name = f"fuzz-vmg-{test_id}-{uuid.uuid4().hex[:8]}"
        vm_spec_override["groupName"] = created_group_name
        # Pre-generate the prereq VM name here (before the try block) so
        # the group manifest can list it by name alongside the test VM.
        if prereq_vm_def:
            prereq_vm_name = f"fuzz-pre-{test_id}-{uuid.uuid4().hex[:8]}"

    if class_spec_override:
        created_class_name = f"fuzz-class-{test_id}-{uuid.uuid4().hex[:8]}"
        class_manifest = factory.vmclass_manifest(created_class_name, namespace, class_spec_override)
    else:
        class_manifest = None
        created_class_name = None

    class_name = created_class_name or base_class_name
    vm_metadata_override = test_entry.get("vm_metadata_override") or {}
    vm_manifest = factory.vm_manifest(
        name=vm_name,
        namespace=namespace,
        image_name=image_name,
        class_name=class_name,
        vm_spec_override=vm_spec_override,
        storage_class=storage_class,
        vm_metadata_override=vm_metadata_override or None,
    )

    result = RunResult(
        test_id=test_id,
        vm_name=vm_name,
        class_name=created_class_name,
        success=False,
        vm_manifest=vm_manifest,
        class_manifest=class_manifest,
    )

    try:
        # Save manifests before apply (for debugging)
        test_artifacts = artifacts_dir / test_id
        test_artifacts.mkdir(parents=True, exist_ok=True)
        with open(test_artifacts / "vm.yaml", "w") as f:
            yaml.dump(vm_manifest, f, default_flow_style=False, sort_keys=False)
        if class_manifest:
            with open(test_artifacts / "vmclass.yaml", "w") as f:
                yaml.dump(class_manifest, f, default_flow_style=False, sort_keys=False)

        # Apply VMClass first if we created one
        if class_manifest:
            runner.apply_manifest(class_manifest)
            time.sleep(2)

        # Create VirtualMachineGroup before VMs.
        # Both VMs must be declared in spec.bootOrder[].members so the group
        # controller can reconcile them and drive placement together.
        # The group is created first so that when VMs set spec.groupName the
        # group already exists and the GroupLinked condition can be satisfied.
        if created_group_name:
            member_names = [vm_name]
            if prereq_vm_name:
                member_names = [prereq_vm_name, vm_name]
            group_manifest = factory.vmgroup_manifest(created_group_name, namespace, member_names)
            with open(test_artifacts / "vmgroup.yaml", "w") as f:
                yaml.dump(group_manifest, f, default_flow_style=False, sort_keys=False)
            runner.apply_manifest(group_manifest)
            print(f"  VMGroup: created {created_group_name} with members {member_names}")
            time.sleep(2)

        # Create and wait for the prerequisite VM before applying the test VM.
        # The prereq must be physically created in vSphere so that its labels are
        # materialised as vSphere tags before PlaceVmsXCluster evaluates the
        # anti-affinity policy for the test VM.
        if prereq_vm_def:
            # prereq_vm_name is pre-generated above when use_vm_group=True so the
            # group manifest can list it; otherwise generate a random name here.
            if prereq_vm_name is None:
                prereq_vm_name = f"fuzz-pre-{test_id}-{uuid.uuid4().hex[:8]}"

            prereq_metadata_override = dict(prereq_vm_def.get("metadata_override") or {})

            prereq_spec_override = dict(prereq_vm_def.get("vm_spec_override") or {})
            if use_vm_group and created_group_name:
                prereq_spec_override["groupName"] = created_group_name

            prereq_manifest = factory.vm_manifest(
                name=prereq_vm_name,
                namespace=namespace,
                image_name=image_name,
                class_name=class_name,
                vm_spec_override=prereq_spec_override,
                storage_class=storage_class,
                vm_metadata_override=prereq_metadata_override or None,
            )
            with open(test_artifacts / "prereq_vm.yaml", "w") as f:
                yaml.dump(prereq_manifest, f, default_flow_style=False, sort_keys=False)
            runner.apply_manifest(prereq_manifest)

            if test_entry.get("prereq_no_wait"):
                # Both anchor and blocked must land in the SAME PlaceVmsXCluster call so
                # DRS evaluates the anti-affinity as a unit (TagSpecs are placement hints,
                # not real vSphere tag operations — they only work when both VMs are sent
                # together).  Waiting for VirtualMachineCreated=True would let the anchor
                # acquire a UniqueID, causing the VMG controller to exclude it from the
                # next group placement call (getVMForPlacement:UniqueID != "").
                # By proceeding immediately, both VMs are pending when the VMG controller
                # first reconciles, so both appear in a single PlaceVmsXCluster request.
                print(f"  Prereq VM: submitted {prereq_vm_name} — proceeding immediately (no wait)")
            else:
                print(f"  Prereq VM: creating {prereq_vm_name} (waiting for vSphere tag materialisation)...")
                if _wait_for_prereq_vm(runner, namespace, prereq_vm_name):
                    print(f"  Prereq VM: created and tags set — proceeding with test VM")
                else:
                    print(
                        f"  Prereq VM: WARNING — {prereq_vm_name} not created within "
                        f"{_PREREQ_VM_CREATED_TIMEOUT}s; anti-affinity test may not fail as expected"
                    )

        runner.apply_manifest(vm_manifest)
        vcenter_tasks_list: list[dict] = []
        reached, reason = runner.wait_until_terminal(
            namespace,
            vm_name,
            timeout,
            vc_si=vc_si,
            vcenter_tasks_out=vcenter_tasks_list if vc_si else None,
        )
        result.success = reached
        result.error_message = reason
        result.vcenter_tasks = vcenter_tasks_list

        vm = runner.get_vm(namespace, vm_name)
        if vm:
            status = vm.get("status", {})
            result.phase = status.get("phase", "")
            result.conditions = status.get("conditions", [])
            lines = []
            for c in result.conditions:
                lines.append(
                    f"  {c.get('type')} | Reason={c.get('reason')} | Status={c.get('status')} | Message={c.get('message', '')}"
                )
            result.conditions_text = "\n".join(lines) if lines else "No conditions"

        result.events = runner.get_events(namespace, vm_name)
        result.events_text = "\n".join(
            f"  {e.get('lastTimestamp')} {e.get('reason')} {e.get('message', '')}"
            for e in result.events
        ) if result.events else "No events"
        result.observed_category = categorize_reasons(result.conditions, result.events)

        # Optional: validate configSpec was applied via pyVmomi when vCenter SI is provided
        if vc_si and result.success and class_spec_override:
            config_spec = class_spec_override.get("configSpec")
            if config_spec:
                try:
                    validator = ConfigSpecValidator(vc_si)
                    result.config_spec_validation = validator.validate(vm_name, config_spec)
                except Exception as e:
                    result.config_spec_validation = {
                        "applied": False,
                        "message": str(e),
                        "mismatches": [],
                        "expected": {},
                        "actual": {},
                    }

    finally:
        # Save live VM/VMClass state before deletion (for debugging)
        test_artifacts = artifacts_dir / test_id
        test_artifacts.mkdir(parents=True, exist_ok=True)
        live_vm = runner.get_vm(namespace, vm_name)
        if live_vm:
            with open(test_artifacts / "vm_live.yaml", "w") as f:
                yaml.dump(live_vm, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        # Write vm_tasks.json when vCenter was connected for task capture (even if empty)
        if vc_si:
            with open(test_artifacts / "vm_tasks.json", "w") as f:
                json.dump(result.vcenter_tasks, f, indent=2, default=str)
        # Save live VMGroup state for debugging (vmgroup_live.yaml)
        if created_group_name:
            vmg_out, _, _ = runner.supervisor.run_kubectl(
                f"get vmg -n {namespace} {created_group_name} -o yaml",
                check=False,
            )
            if vmg_out:
                with open(test_artifacts / "vmgroup_live.yaml", "w") as f:
                    f.write(vmg_out)
        # Cleanup: delete VM then VMClass unless --no-delete; always delete prereq VM
        # and VMGroup (VMs must go first so owner-reference GC doesn't race with us).
        if not keep_vm:
            runner.delete_vm(namespace, vm_name)
            if created_class_name:
                runner.delete_vmclass(namespace, created_class_name)
        if prereq_vm_name:
            runner.delete_vm(namespace, prereq_vm_name)
        if created_group_name:
            runner.delete_vmgroup(namespace, created_group_name)
    return result


# -----------------------------------------------------------------------------
# Reporter: standalone HTML with CSS tabs/filters
# -----------------------------------------------------------------------------
def _failure_or_error_text(result: RunResult) -> str:
    """Preferred failure condition text, or error message."""
    if result.conditions_text and result.conditions_text.strip() != "No conditions":
        return result.conditions_text.strip()
    return result.error_message or ""


def _result_to_status_dict(r: RunResult) -> dict:
    """Build a JSON-serializable dict with complete status for a single result."""
    d = {
        "test_id": r.test_id,
        "vm_name": r.vm_name,
        "class_name": r.class_name,
        "success": r.success,
        "phase": r.phase,
        "observed_category": r.observed_category,
        "error_message": r.error_message,
        "conditions": r.conditions,
        "conditions_text": r.conditions_text,
        "events": r.events,
        "events_text": r.events_text,
        "vm_manifest": r.vm_manifest,
        "class_manifest": r.class_manifest,
    }
    if r.config_spec_validation is not None:
        d["config_spec_validation"] = r.config_spec_validation
    if r.vcenter_tasks:
        d["vcenter_tasks"] = r.vcenter_tasks
    return d


def render_json_report(results: list[RunResult], output_path: Path) -> None:
    """Write report with complete status for each result in JSON format."""
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": [_result_to_status_dict(r) for r in results],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )


def render_html_report(
    results: list[RunResult], output_path: Path, registry: list[dict], json_report_path: Path | None = None
) -> None:
    """Write a standalone HTML file with test results, failure/error messages, and complete status as JSON."""
    rows = []
    for r in results:
        art_link = f"{r.test_id}/"
        failure_text = _failure_or_error_text(r)
        status_json = json.dumps(_result_to_status_dict(r), indent=2, default=str)
        status_json_escaped = _escape(status_json)
        art_label = "artifacts"
        if r.vcenter_tasks:
            art_label = f"artifacts (vCenter tasks: {len(r.vcenter_tasks)})"
        rows.append(
            f"""
            <tr>
              <td>{r.test_id}</td>
              <td>{r.phase}</td>
              <td>{'Yes' if r.success else 'No'}</td>
              <td><pre>{_escape(failure_text)}</pre></td>
              <td><details><summary>Show</summary><pre class="status-json">{status_json_escaped}</pre></details></td>
              <td><a href="{art_link}">{_escape(art_label)}</a></td>
            </tr>"""
        )

    json_link = ""
    if json_report_path and json_report_path.exists():
        json_link = f'  <p><a href="{json_report_path.name}">Full report (JSON)</a></p>\n'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VM Operator Fuzzer Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 1rem 2rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
    th {{ background: #f0f0f0; }}
    pre {{ margin: 0; font-size: 0.85em; white-space: pre-wrap; max-width: 600px; }}
    pre.status-json {{ max-height: 20em; overflow: auto; font-size: 0.75em; }}
  </style>
</head>
<body>
  <h1>VM Operator Fuzzer Report</h1>
{json_link}
  <table>
    <thead>
      <tr>
        <th>Test ID</th>
        <th>Phase</th>
        <th>Terminal</th>
        <th>Failure / Error</th>
        <th>Status (JSON)</th>
        <th>Artifacts</th>
      </tr>
    </thead>
    <tbody>
      {"".join(rows)}
    </tbody>
  </table>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _load_success_history(artifacts_dir: Path) -> set[str]:
    """Load set of test IDs that completed successfully in previous runs."""
    path = artifacts_dir / SUCCESS_HISTORY_FILENAME
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        ids = data.get("successful_ids", data) if isinstance(data, dict) else data
        return set(ids) if isinstance(ids, list) else set()
    except (json.JSONDecodeError, OSError):
        return set()


def _save_success_history(artifacts_dir: Path, successful_ids: set[str]) -> None:
    """Persist successful test IDs for future skip-when-not-run-all runs."""
    path = artifacts_dir / SUCCESS_HISTORY_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"successful_ids": sorted(successful_ids), "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            indent=2,
        ),
        encoding="utf-8",
    )


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="VM Operator negative testing / fuzzing (v1alpha5 & v1alpha6)."
    )
    parser.add_argument("--vmi", required=True, help="VirtualMachineImage name (required)")
    parser.add_argument(
        "--api-version",
        choices=SUPPORTED_API_VERSIONS,
        default=DEFAULT_API_VERSION,
        help=f"API version (default: {DEFAULT_API_VERSION})",
    )
    parser.add_argument("--namespace", default="default", help="Kubernetes namespace")
    parser.add_argument("--storage-class", default="wcpglobal-storage-profile", help="StorageClass for VMs")
    parser.add_argument("--vm-class", default="", help="Base VM Class name (used when test does not override class)")
    parser.add_argument("--timeout", type=int, default=VM_TERMINAL_WAIT_TIMEOUT, help="Max wait for VM terminal state in seconds (default: 300 = 5 min)")
    parser.add_argument(
        "--output-dir",
        default="",
        help="Output folder for artifacts and report (default: hack/artifacts)",
    )
    parser.add_argument(
        "--output",
        default="",
        help="HTML report path override (default: <output-dir>/fuzzer_report.html)",
    )
    parser.add_argument("--test", default="", help="Run only this single test by id (e.g. --test configspec-extraconfig-huge)")
    parser.add_argument("--tests", default="", help="Comma-separated test ids to run (default: all). Ignored if --test is set.")
    parser.add_argument(
        "--run-all",
        action="store_true",
        help="Run all scenarios regardless of previous runs. If not set, scenarios that completed successfully in a prior run are skipped.",
    )
    parser.add_argument(
        "--no-delete",
        action="store_true",
        help="Do not delete VM or VMClass after each scenario (default: delete after run).",
    )
    parser.add_argument(
        "--validate-configspec",
        action="store_true",
        help="Validate configSpec was applied on the VM using pyVmomi (keeps vCenter connection open during run).",
    )
    parser.add_argument(
        "--capture-vcenter-tasks",
        action="store_true",
        help="Capture vCenter tasks for the VM during the wait-for-terminal period (keeps vCenter connection open; writes vm_tasks.json per test).",
    )

    # Direct Supervisor path — connect straight to Supervisor without going through vCenter.
    # Use when you already have the Supervisor control-plane IP and password (e.g. from a
    # previous run of decryptK8Pwd.py, or from a pre-provisioned environment).
    parser.add_argument("--supervisor-ip", help="Supervisor control-plane IP (direct mode; skips vCenter credential discovery)")
    parser.add_argument("--supervisor-password", help="Supervisor SSH password (direct mode)")
    parser.add_argument("--supervisor-user", default="root", help="Supervisor SSH user (default: root)")

    # vCenter path (Supervisor credentials via decryptK8Pwd.py on the vCenter node).
    # Required when --supervisor-ip/--supervisor-password are not provided.
    # Also required for --validate-configspec and --capture-vcenter-tasks even in direct mode.
    parser.add_argument("--vcenter", help="vCenter host (required when not using --supervisor-ip)")
    parser.add_argument("--vcenter-user", default=DEFAULT_VCENTER_USER, help="vCenter user")
    parser.add_argument("--vcenter-password", help="vCenter API password")
    parser.add_argument("--vcenter-root-password", help="vCenter root SSH password for decryptK8Pwd.py (default: same as vcenter-password)")

    args = parser.parse_args()

    # Resolve base VM class: from args or we must discover (requires Supervisor)
    base_class_name = args.vm_class.strip()

    # Determine connection mode:
    #   Direct mode  – --supervisor-ip + --supervisor-password provided.
    #   vCenter mode – --vcenter + --vcenter-password provided (uses decryptK8Pwd.py).
    # Both modes can coexist: --supervisor-ip skips credential discovery while
    # --vcenter is still used for --validate-configspec / --capture-vcenter-tasks.
    use_direct_supervisor = bool(
        getattr(args, "supervisor_ip", None) and getattr(args, "supervisor_password", None)
    )
    use_vcenter = bool(args.vcenter and args.vcenter_password)

    if not use_direct_supervisor and not use_vcenter:
        print(
            "ERROR: Provide Supervisor credentials via one of:\n"
            "  --supervisor-ip <IP> --supervisor-password <PWD>   (direct Supervisor mode)\n"
            "  --vcenter <VC> --vcenter-password <PWD>            (vCenter credential discovery)"
        )
        return 1

    if not _HAS_PARAMIKO:
        print("ERROR: paramiko is required. pip install paramiko")
        return 1

    if use_vcenter and not _HAS_PYVMOMI:
        print("ERROR: pyVmomi is required for vCenter mode. pip install pyVmomi")
        return 1

    # Resolve Supervisor IP / password.
    vc: Any = None
    vc_connected_for_validation = False

    if use_direct_supervisor:
        # Use credentials provided directly — no vCenter SSH required.
        supervisor_ip: str = args.supervisor_ip
        supervisor_password: str = args.supervisor_password
        supervisor_user: str = getattr(args, "supervisor_user", "root") or "root"
        print(f"Using direct Supervisor connection: {supervisor_ip} (user: {supervisor_user})")

        # Optionally connect to vCenter for validation / task capture.
        if use_vcenter and (args.validate_configspec or args.capture_vcenter_tasks):
            root_password = args.vcenter_root_password or args.vcenter_password
            vc = VCenterClient(args.vcenter, args.vcenter_user, args.vcenter_password, root_password)
            vc.connect(ssh=False)
            vc_connected_for_validation = True
    else:
        # vCenter path: connect to vCenter, run decryptK8Pwd.py to retrieve Supervisor creds.
        supervisor_user = "root"
        root_password = args.vcenter_root_password or args.vcenter_password
        vc = VCenterClient(args.vcenter, args.vcenter_user, args.vcenter_password, root_password)
        vc.connect()
        vc_connected_for_validation = bool(args.validate_configspec or args.capture_vcenter_tasks)
        try:
            supervisor_ip, supervisor_password = vc.get_supervisor_credentials()
        except RuntimeError as e:
            print(f"ERROR: {e}")
            return 1
        finally:
            if not vc_connected_for_validation:
                vc.disconnect()
                vc = None

    # One-off SupervisorClient for namespace check and VMClass discovery; then disconnect.
    _supervisor = SupervisorClient(supervisor_ip, supervisor_password, supervisor_user)
    _supervisor.connect()
    try:
        if not _supervisor.namespace_exists(args.namespace):
            print(f"ERROR: Namespace '{args.namespace}' does not exist.")
            return 1
        if not base_class_name:
            out, _, rc = _supervisor.run_kubectl(f"get vmclass -n {args.namespace} -o json", check=False)
            if rc != 0 or not out:
                out, _, rc = _supervisor.run_kubectl("get vmclass -o json", check=False)
            if rc == 0 and out:
                try:
                    data = json.loads(out)
                    items = data.get("items", [])
                    if items:
                        base_class_name = items[0].get("metadata", {}).get("name", "")
                except json.JSONDecodeError:
                    pass
            if not base_class_name:
                print("ERROR: No VMClass found. Provide --vm-class or ensure namespace has a VMClass.")
                return 1
            print(f"Using VM Class: {base_class_name}")
    finally:
        _supervisor.disconnect()

    # Filter registry by --test (single id) or --tests (comma-separated ids)
    registry = list(INITIAL_PAYLOADS)
    test_filter = (args.test or args.tests or "").strip()
    if test_filter:
        if args.test:
            want = {test_filter}
        else:
            want = {t.strip() for t in args.tests.split(",") if t.strip()}
        registry = [e for e in registry if e["id"] in want]
        if not registry:
            print("ERROR: No matching test ids.")
            return 1

    artifacts_dir = Path(args.output_dir) if args.output_dir else ARTIFACTS_BASE
    artifacts_dir = artifacts_dir.resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # When --run-all is not set: skip scenarios that completed successfully in a previous run.
    successful_ids: set[str] = set()
    if not args.run_all:
        successful_ids = _load_success_history(artifacts_dir)
        if successful_ids:
            registry_ids = {e["id"] for e in registry}
            skipped_ids = registry_ids & successful_ids
            registry = [e for e in registry if e["id"] not in successful_ids]
            if skipped_ids:
                print(f"Skipping {len(skipped_ids)} scenario(s) already run successfully in a prior run: {sorted(skipped_ids)}")
        if not registry:
            print("All selected scenarios were already run successfully. Use --run-all to run everything.")
            return 0

    factory = ManifestFactory(args.api_version)
    supervisor = SupervisorClient(supervisor_ip, supervisor_password, supervisor_user)
    supervisor.connect()
    try:
        runner = KubeRunner(supervisor)

        # Discover zone topology before running tests.
        # Used to:
        #  1. Print cluster topology for context/diagnostics.
        #  2. Pin prereq VMs to a known zone (pin_prereq_to_first_zone).
        #  3. Save zones.json to the artifacts dir for reference.
        zones = runner.discover_zones(args.namespace)
        if zones:
            print(f"\nDiscovered {len(zones)} zone(s) in namespace '{args.namespace}':")
            for z in zones:
                print(f"  [{z.cr_type}] {z.name}")
                if z.pool_mo_ids:
                    print(f"    PoolMoIDs:    {z.pool_mo_ids}")
                if z.folder_mo_id:
                    print(f"    FolderMoID:   {z.folder_mo_id}")
                if z.cluster_mo_ids:
                    print(f"    ClusterMoIDs: {z.cluster_mo_ids}")
                if z.status:
                    print(f"    Status:       {z.status}")
            if len(zones) == 1:
                print(
                    f"  NOTE: single zone detected — zone-anti-affinity tests are "
                    f"expected to trigger VirtualMachinePlacementReady=False"
                )
            zones_path = artifacts_dir / "zones.json"
            with open(zones_path, "w") as _zf:
                json.dump(
                    [
                        {
                            "name": z.name,
                            "cr_type": z.cr_type,
                            "pool_mo_ids": z.pool_mo_ids,
                            "folder_mo_id": z.folder_mo_id,
                            "cluster_mo_ids": z.cluster_mo_ids,
                            "spec": z.spec,
                            "status": z.status,
                        }
                        for z in zones
                    ],
                    _zf,
                    indent=2,
                )
            print(f"  Zone info saved: {zones_path}")
        else:
            print(f"\nWARNING: No zones discovered in namespace '{args.namespace}'")

        results: list[RunResult] = []
        for entry in registry:
            print(f"\nRunning: {entry['id']} ({entry.get('category', '')}) ...")
            try:
                vc_si = vc.si if (vc_connected_for_validation and vc) else None
                res = run_single_test(
                    runner,
                    factory,
                    args.namespace,
                    args.vmi,
                    base_class_name,
                    args.storage_class,
                    entry,
                    artifacts_dir,
                    args.timeout,
                    keep_vm=args.no_delete,
                    vc_si=vc_si,
                    zones=zones,
                )
                results.append(res)
                if res.success and not args.run_all:
                    successful_ids.add(res.test_id)
                    _save_success_history(artifacts_dir, successful_ids)
                print(f"  Phase: {res.phase}")
                print(f"  Category: {res.observed_category}")
                print(f"  Terminal: {'Yes' if res.success else 'No'}")
                if res.error_message:
                    print(f"  Error/Reason: {res.error_message[:300]}")
                if res.conditions_text:
                    print("  Conditions:")
                    for line in res.conditions_text.strip().split("\n"):
                        print(f"    {line}")
                else:
                    print("  Conditions: (none)")
                if res.events_text:
                    print("  Events:")
                    for line in res.events_text.strip().split("\n")[:10]:
                        print(f"    {line}")
                    if len(res.events_text.strip().split("\n")) > 10:
                        print("    ...")
                if res.config_spec_validation is not None:
                    v = res.config_spec_validation
                    applied = v.get("applied", False)
                    print(f"  ConfigSpec (pyVmomi): {'Applied' if applied else 'Not applied'}")
                    if not applied and v.get("message"):
                        print(f"    {v['message']}")
                print(f"  Artifacts: {artifacts_dir / res.test_id}")
            except Exception as e:
                print(f"  -> ERROR: {e}")
                results.append(
                    RunResult(
                        test_id=entry["id"],
                        vm_name="",
                        class_name=None,
                        success=False,
                        error_message=str(e),
                    )
                )
    finally:
        supervisor.disconnect()
        if vc_connected_for_validation and vc:
            vc.disconnect()

    out_path = Path(args.output) if args.output else artifacts_dir / "fuzzer_report.html"
    json_path = out_path.with_suffix(".json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    render_json_report(results, json_path)
    render_html_report(results, out_path, registry, json_report_path=json_path)
    print(f"\nOutput folder: {artifacts_dir}")
    print(f"Report (HTML): {out_path}")
    print(f"Report (JSON): {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
