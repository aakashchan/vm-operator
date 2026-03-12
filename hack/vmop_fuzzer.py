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
  # With ovf-deploy-test (vCenter + Supervisor via decryptK8Pwd):
  python hack/vmop_fuzzer.py --vmi <vmi-name> --vcenter <vc-ip> --vcenter-password <pwd> --namespace <ns>

  # API version and namespace:
  python hack/vmop_fuzzer.py --vmi my-image --api-version v1alpha6 --namespace my-ns ...

  # Optional: kubeconfig (if not using vCenter/Supervisor path)
  python hack/vmop_fuzzer.py --vmi my-image --kubeconfig /path/to/kubeconfig --namespace my-ns

Requirements:
  pip install pyyaml
  For ovf-deploy-test path: run from hack/ovf-deploy-test or set PYTHONPATH to it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# -----------------------------------------------------------------------------
# Path setup for ovf-deploy-test (SupervisorClient / VCenterClient)
# -----------------------------------------------------------------------------
_HACK_DIR = Path(__file__).resolve().parent
_OVF_DEPLOY_DIR = _HACK_DIR / "ovf-deploy-test"
if str(_OVF_DEPLOY_DIR) not in sys.path:
    sys.path.insert(0, str(_OVF_DEPLOY_DIR))

_SupervisorClient = None
_VCenterClient = None
_DEFAULT_VCENTER_USER = "administrator@vsphere.local"

try:
    from ovf_deploy_test import (  # type: ignore[import-untyped]
        VCenterClient as _VCenterClient,
        SupervisorClient as _SupervisorClient,
        DEFAULT_VCENTER_USER as _DEFAULT_VCENTER_USER,
    )
except ImportError:
    pass

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
        "id": "configspec-vgpu-vmiop",
        "category": CAT_PLACEMENT,
        "description": "configSpec.deviceChange: add VirtualPCIPassthrough with VirtualPCIPassthroughVmiopBackingInfo (non-existent vGPU)",
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
                            "_typeName": "VirtualPCIPassthrough",
                            "key": -1,
                            "backing": {
                                "_typeName": "VirtualPCIPassthroughVmiopBackingInfo",
                                "vgpu": "non-existent-vgpu-profile",
                            },
                        },
                    },
                ],
            },
        },
    },
    {
        "id": "configspec-dynamic-pci",
        "category": CAT_PLACEMENT,
        "description": "configSpec.deviceChange: add VirtualPCIPassthrough with VirtualPCIPassthroughDynamicBackingInfo (invalid vendor/device)",
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
                            "_typeName": "VirtualPCIPassthrough",
                            "key": -1,
                            "backing": {
                                "_typeName": "VirtualPCIPassthroughDynamicBackingInfo",
                                "deviceName": "",
                                "allowedDevice": [
                                    {
                                        "_typeName": "VirtualPCIPassthroughAllowedDevice",
                                        "vendorId": 0,
                                        "deviceId": 0,
                                    },
                                ],
                            },
                        },
                    },
                ],
            },
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
        storage_class: str = "wcpglobal-storage-profile",
        power_state: str = "PoweredOn",
        guest_id: str = "vmwarePhoton64Guest",
    ) -> dict[str, Any]:
        base_spec: dict[str, Any] = {
            "imageName": image_name,
            "className": class_name,
            "storageClass": storage_class,
            "powerState": power_state,
            "guestID": guest_id,
        }
        spec = _deep_merge(base_spec, vm_spec_override)
        return {
            "apiVersion": self.api_prefix,
            "kind": "VirtualMachine",
            "metadata": {"name": name, "namespace": namespace},
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


class KubeRunner:
    """Apply/Watch/Delete VM (and optional VMClass); capture status.conditions and events."""

    def __init__(self, supervisor_client: Any) -> None:
        self.supervisor = supervisor_client

    def apply_manifest(self, manifest: dict) -> None:
        """Apply a single manifest (VM or VMClass) via kubectl."""
        yaml_content = yaml.dump(manifest, default_flow_style=False, sort_keys=False)
        cmd = f"cat <<'VMEOF' | kubectl apply -f -\n{yaml_content}\nVMEOF"
        stdin, stdout, stderr = self.supervisor.ssh.exec_command(cmd)
        exit_code = stdout.channel.recv_exit_status()
        err = stderr.read().decode()
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

    def wait_until_terminal(
        self,
        namespace: str,
        vm_name: str,
        timeout: int = VM_TERMINAL_WAIT_TIMEOUT,
    ) -> tuple[bool, str]:
        """Poll VM until it reaches a terminal state, or timeout (at most 5 min). Returns (reached, last_reason).
        Terminal: status.phase in (Created, Running, Failed, Unknown), or v1alpha5/v1alpha6 without phase:
        VirtualMachineCreated condition True (VM created) or any condition status False (failure).
        """
        start = time.time()
        last_reason = ""
        while time.time() - start < timeout:
            vm = self.get_vm(namespace, vm_name)
            if vm:
                status = vm.get("status", {})
                phase = status.get("phase", "")
                conditions = status.get("conditions", [])
                if not conditions:
                    time.sleep(POLL_INTERVAL)
                    continue
                # APIs that set phase (e.g. v1alpha1)
                if phase in ("Created", "Running", "Failed", "Unknown"):
                    reason = getattr(
                        self.supervisor, "get_vm_status_reason", lambda ns, n: ""
                    )(namespace, vm_name)
                    if not reason:
                        for c in conditions:
                            if c.get("status") == "False":
                                reason = c.get("reason", "") or c.get("message", "")
                                break
                    return True, reason or phase
                # v1alpha5/v1alpha6: no status.phase; use conditions
                created_ok = any(
                    c.get("type") == "VirtualMachineCreated" and c.get("status") == "True"
                    for c in conditions
                )
                any_failed = any(c.get("status") == "False" for c in conditions)
                if created_ok or any_failed:
                    for c in conditions:
                        if c.get("status") == "False":
                            last_reason = c.get("reason") or c.get("message", "")
                            break
                    return True, last_reason or ("Created" if created_ok else "Failed")
                # Build last_reason for timeout message
                for c in conditions:
                    if c.get("status") == "False":
                        last_reason = c.get("reason") or c.get("message") or last_reason
            time.sleep(POLL_INTERVAL)
        return False, last_reason or "timeout"


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
) -> RunResult:
    """Run one test from the registry: create VM (and optional class), wait, capture, cleanup (with manifest save)."""
    test_id = test_entry["id"]
    vm_name = f"fuzz-{test_id}-{uuid.uuid4().hex[:8]}"
    vm_spec_override = test_entry.get("vm_spec_override") or {}
    class_spec_override = test_entry.get("class_spec_override")
    created_class_name: str | None = None

    if class_spec_override:
        created_class_name = f"fuzz-class-{test_id}-{uuid.uuid4().hex[:8]}"
        class_manifest = factory.vmclass_manifest(created_class_name, namespace, class_spec_override)
    else:
        class_manifest = None
        created_class_name = None

    class_name = created_class_name or base_class_name
    vm_manifest = factory.vm_manifest(
        name=vm_name,
        namespace=namespace,
        image_name=image_name,
        class_name=class_name,
        vm_spec_override=vm_spec_override,
        storage_class=storage_class,
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

        runner.apply_manifest(vm_manifest)
        reached, reason = runner.wait_until_terminal(namespace, vm_name, timeout)
        result.success = reached
        result.error_message = reason

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

    finally:
        # Save live VM/VMClass state before deletion (for debugging)
        test_artifacts = artifacts_dir / test_id
        test_artifacts.mkdir(parents=True, exist_ok=True)
        live_vm = runner.get_vm(namespace, vm_name)
        if live_vm:
            with open(test_artifacts / "vm_live.yaml", "w") as f:
                yaml.dump(live_vm, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        # 100% cleanup: delete VM then VMClass
        runner.delete_vm(namespace, vm_name)
        if created_class_name:
            runner.delete_vmclass(namespace, created_class_name)
    return result


# -----------------------------------------------------------------------------
# Reporter: standalone HTML with CSS tabs/filters
# -----------------------------------------------------------------------------
def _failure_or_error_text(result: RunResult) -> str:
    """Preferred failure condition text, or error message."""
    if result.conditions_text and result.conditions_text.strip() != "No conditions":
        return result.conditions_text.strip()
    return result.error_message or ""


def render_html_report(results: list[RunResult], output_path: Path, registry: list[dict]) -> None:
    """Write a standalone HTML file with test results and failure/error messages."""
    rows = []
    for r in results:
        art_link = f"{r.test_id}/"
        failure_text = _failure_or_error_text(r)
        rows.append(
            f"""
            <tr>
              <td>{r.test_id}</td>
              <td>{r.phase}</td>
              <td>{'Yes' if r.success else 'No'}</td>
              <td><pre>{_escape(failure_text)}</pre></td>
              <td><a href="{art_link}">artifacts</a></td>
            </tr>"""
        )

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
  </style>
</head>
<body>
  <h1>VM Operator Fuzzer Report</h1>
  <table>
    <thead>
      <tr>
        <th>Test ID</th>
        <th>Phase</th>
        <th>Terminal</th>
        <th>Failure / Error</th>
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
    parser.add_argument("--tests", default="", help="Comma-separated test ids to run (default: all)")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="Number of scenarios per batch; each batch uses a new SupervisorClient (default: 1)",
    )
    parser.add_argument(
        "--run-all",
        action="store_true",
        help="Run all scenarios regardless of previous runs. If not set, scenarios that completed successfully in a prior run are skipped.",
    )

    # ovf-deploy-test path (vCenter + Supervisor)
    parser.add_argument("--vcenter", help="vCenter host (required for Supervisor path)")
    parser.add_argument("--vcenter-user", default=_DEFAULT_VCENTER_USER, help="vCenter user")
    parser.add_argument("--vcenter-password", help="vCenter password")
    parser.add_argument("--vcenter-root-password", help="vCenter root SSH password (default: same as vcenter-password)")

    args = parser.parse_args()

    # Resolve base VM class: from args or we must discover (requires Supervisor)
    base_class_name = args.vm_class.strip()
    use_supervisor = bool(args.vcenter and args.vcenter_password)
    if use_supervisor and not base_class_name and _SupervisorClient:
        # Discover first available VMClass in namespace
        try:
            out, _, rc = None, None, 1
            # Run kubectl via a one-off client if we have not connected yet; we connect below
            pass
        except Exception:
            pass
        # We'll set base_class_name after we have supervisor
    if not use_supervisor:
        if not base_class_name:
            print("ERROR: Without --vcenter/--vcenter-password we need --vm-class to be set.")
            return 1
        print("ERROR: kubeconfig-only mode not implemented; use --vcenter and --vcenter-password with ovf-deploy-test.")
        return 1

    if not _SupervisorClient or not _VCenterClient:
        print("ERROR: ovf_deploy_test not found. Run from hack/ovf-deploy-test or set PYTHONPATH to it.")
        return 1

    # Connect: vCenter -> Supervisor credentials -> SupervisorClient
    root_password = args.vcenter_root_password or args.vcenter_password
    vc = _VCenterClient(
        args.vcenter,
        args.vcenter_user,
        args.vcenter_password,
        root_password,
    )
    vc.connect()
    try:
        supervisor_ip, supervisor_password = vc.get_supervisor_credentials()
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vc.disconnect()

    # One-off supervisor for namespace check and VM class discovery; then disconnect.
    _supervisor = _SupervisorClient(supervisor_ip, supervisor_password)
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

    # Filter registry by --tests
    registry = list(INITIAL_PAYLOADS)
    if args.tests:
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

    batch_size = max(1, int(args.batch_size))
    batches = [
        registry[i : i + batch_size]
        for i in range(0, len(registry), batch_size)
    ]
    factory = ManifestFactory(args.api_version)

    results: list[RunResult] = []
    for batch_idx, batch in enumerate[list[dict[str, Any]]](batches):
        # Each batch uses its own SupervisorClient (no sharing across batches).
        supervisor = _SupervisorClient(supervisor_ip, supervisor_password)
        supervisor.connect()
        try:
            runner = KubeRunner(supervisor)
            for entry in batch:
                print(f"\nRunning: {entry['id']} ({entry.get('category', '')}) [batch {batch_idx + 1}/{len(batches)}] ...")
                try:
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

    out_path = Path(args.output) if args.output else artifacts_dir / "fuzzer_report.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    render_html_report(results, out_path, registry)
    print(f"\nOutput folder: {artifacts_dir}")
    print(f"Report: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
