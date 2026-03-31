#!/usr/bin/env python3
# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

# ABOUTME: Script to test OVF deployment via VM Service on Supervisor.
# ABOUTME: Uploads OVF to Content Library via pyvmomi, deploys VM via kubectl.

"""
ovf_deploy_test.py - Test OVF deployment via VM Service

This script:
1. Connects to vCenter using pyvmomi (API)
2. SSHs to vCenter as root to retrieve Supervisor credentials via decryptK8Pwd.py
3. Uploads an OVF from a URL to a Content Library
4. SSHs to Supervisor and deploys a VM using VM Service
5. Waits for VM to get an IP and verifies reachability

Usage:
    python ovf_deploy_test.py \
        --vcenter <vcenter-ip> \
        --vcenter-password <vc-api-password> \
        --vcenter-root-password <vc-root-ssh-password>

    # If vCenter API password and root SSH password are the same:
    python ovf_deploy_test.py \
        --vcenter <vcenter-ip> \
        --vcenter-password <password>

Requirements:
    pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import concurrent.futures
import io
import json
import os
import re
import ssl
import sys
import tarfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import paramiko
import requests
import yaml
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

# Disable SSL warnings for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default values
DEFAULT_OVF_BASE_URL = "https://packages.vcfd.broadcom.net/ui/native/cls-generic-virtual/testdata/"
DEFAULT_OVF_URL = "https://packages.vcfd.broadcom.net/artifactory/cls-generic-virtual/testdata/BIGIP-16.0.1.1-0.0.6.ALL-vmware.ova"
DEFAULT_NAMESPACE = "ovftest"
DEFAULT_CONTENT_LIBRARY = "ovftest"
DEFAULT_VM_CLASS = "best-effort-xsmall"
DEFAULT_VCENTER_USER = "administrator@vsphere.local"
STORAGE_CLASS = "wcpglobal-storage-profile"
DEFAULT_VM_VERSION = "v1alpha5"
DEFAULT_SUBNET_PREFIX_LENGTH = 24


# Timeouts
VMI_WAIT_TIMEOUT = 60  # 1 minute
VM_TOOLS_WAIT_TIMEOUT = 600  # 10 minutes
POLL_INTERVAL = 10  # seconds

class UntrustedSourceError(RuntimeError):
    """Raised when vCenter cannot trust the source server's TLS certificate."""


class SetupError(RuntimeError):
    """
    Raised when the test harness fails before the VM is deployed —
    e.g. content library upload error, VMI never appeared, kubectl failure.
    These are infrastructure/script problems, not OVF compatibility issues.
    """


# OVF XML namespaces — OVF 1.x (DMTF) and OVF 0.9 (VMware legacy)
OVF_NS   = "http://schemas.dmtf.org/ovf/envelope/1"
OVF09_NS = "http://www.vmware.com/schema/ovf/1/envelope"
VMW_NS   = "http://www.vmware.com/schema/ovf"
RASD_NS  = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"

# OVF 0.9 xsi:type values that identify OS and hardware sections
_OVF09_OS_TYPE   = "ovf:OperatingSystemSection_Type"
_OVF09_VHW_TYPE  = "ovf:VirtualHardwareSection_Type"

# Map of OVF 0.9 Description text substrings → vmw:osType equivalents
# Used as a fallback when vmw:osType is absent (OVF 0.9 schema).
_OVF09_OS_DESC_MAP = [
    ("32-bit", "otherLinuxGuest"),
    ("64-bit", "otherLinux64Guest"),
]


@dataclass
class OvfProperty:
    """Represents a single OVF property from ProductSection."""
    key: str
    type: str
    default: str
    user_configurable: bool
    label: str
    description: str
    qualifiers: str = ""  # vmw:qualifiers e.g. "Ip('Network 1')", "Netmask('Network 1')"


@dataclass
class OvfNetwork:
    """Represents a logical network defined in the OVF NetworkSection."""
    name: str
    description: str


@dataclass
class OvfInfo:
    """Parsed information from an OVF envelope."""
    name: str
    networks: list[OvfNetwork] = field(default_factory=list)
    properties: list[OvfProperty] = field(default_factory=list)
    is_vapp: bool = False
    guest_id: str = ""  # OVF OperatingSystemSection osType, empty if not specified
    has_buslogic: bool = False  # True if OVF has a BusLogic SCSI controller

    def has_properties(self) -> bool:
        return len(self.properties) > 0

    def has_networks(self) -> bool:
        return len(self.networks) > 0


def parse_ovf(ovf_content: str) -> OvfInfo:
    """
    Parse an OVF XML string and extract networks and vApp properties.

    Args:
        ovf_content: OVF XML as a string

    Returns:
        OvfInfo with parsed networks and properties
    """
    root = ET.fromstring(ovf_content)

    # Detect OVF schema version from root namespace
    is_ovf09 = root.tag.startswith(f"{{{OVF09_NS}}}")

    # A vApp envelope has VirtualSystemCollection as the top-level content element.
    is_vapp = root.find(f"{{{OVF_NS}}}VirtualSystemCollection") is not None

    # Get VM name
    name_el = root.find(f".//{{{OVF_NS}}}VirtualSystem/{{{OVF_NS}}}Name")
    name = name_el.text if name_el is not None else "unknown"

    info = OvfInfo(name=name, is_vapp=is_vapp)

    # Parse OperatingSystemSection for guestId.
    # OVF 1.x: <OperatingSystemSection vmw:osType="..."> — prefer vmw:osType attribute,
    #           fall back to Description text if attribute absent.
    # OVF 0.9: <Section xsi:type="ovf:OperatingSystemSection_Type"><Description>...</Description>
    os_section = root.find(f".//{{{OVF_NS}}}OperatingSystemSection")
    if os_section is not None:
        info.guest_id = os_section.get(f"{{{VMW_NS}}}osType", "")
        if not info.guest_id:
            # No vmw:osType — derive from Description text (e.g. "Other Linux (32-bit)")
            desc_el = os_section.find(f"{{{OVF_NS}}}Description")
            if desc_el is None:
                desc_el = os_section.find("Description")
            desc_text = (desc_el.text or "").lower() if desc_el is not None else ""
            for substr, guest_id in _OVF09_OS_DESC_MAP:
                if substr in desc_text:
                    info.guest_id = guest_id
                    break
    elif is_ovf09:
        # OVF 0.9: find Section with xsi:type containing OperatingSystemSection_Type
        xsi_type_attr = "{http://www.w3.org/2001/XMLSchema-instance}type"
        for section in root.iter():
            if section.get(xsi_type_attr, "") == _OVF09_OS_TYPE:
                desc_el = section.find("Description")
                if desc_el is None:
                    # Description may be unnamespaced or under OVF09_NS
                    desc_el = section.find(f"{{{OVF09_NS}}}Description")
                desc_text = (desc_el.text or "").lower() if desc_el is not None else ""
                for substr, guest_id in _OVF09_OS_DESC_MAP:
                    if substr in desc_text:
                        info.guest_id = guest_id
                        break
                break

    # Detect BusLogic SCSI controller (ResourceType=6, ResourceSubType=buslogic).
    # Item elements appear in the OVF namespace, RASD namespace, or OVF 0.9 namespace
    # depending on the OVF producer and schema version.
    for item in (root.findall(f".//{{{OVF_NS}}}Item") +
                 root.findall(f".//{{{RASD_NS}}}Item") +
                 root.findall(f".//{{{OVF09_NS}}}Item") +
                 root.findall(".//Item")):
        # Children may use RASD_NS or a local alias — check both
        res_type = (item.findtext(f"{{{RASD_NS}}}ResourceType", "") or
                    item.findtext("ResourceType", ""))
        res_subtype = (item.findtext(f"{{{RASD_NS}}}ResourceSubType", "") or
                       item.findtext("ResourceSubType", "")).lower()
        if res_type == "6" and "buslogic" in res_subtype:
            info.has_buslogic = True
            break

    # Parse NetworkSection
    for net in root.findall(f".//{{{OVF_NS}}}NetworkSection/{{{OVF_NS}}}Network"):
        net_name = net.get(f"{{{OVF_NS}}}name", "")
        desc_el = net.find(f"{{{OVF_NS}}}Description")
        desc = desc_el.text if desc_el is not None else ""
        info.networks.append(OvfNetwork(name=net_name, description=desc))

    # Parse ProductSection properties.
    # When a ProductSection has ovf:class and ovf:instance (vAMI convention),
    # vCenter composes the effective property key as "{class}.{bare_key}.{instance}".
    for section in root.findall(f".//{{{OVF_NS}}}ProductSection"):
        cls = section.get(f"{{{OVF_NS}}}class", "")
        instance = section.get(f"{{{OVF_NS}}}instance", "")
        for prop in section.findall(f"{{{OVF_NS}}}Property"):
            bare_key = prop.get(f"{{{OVF_NS}}}key", "")
            if cls and instance:
                key = f"{cls}.{bare_key}.{instance}"
            else:
                key = bare_key
            typ = prop.get(f"{{{OVF_NS}}}type", "string")
            default = prop.get(f"{{{OVF_NS}}}value", "")
            user_configurable = prop.get(f"{{{OVF_NS}}}userConfigurable", "false").lower() == "true"
            qualifiers = prop.get(f"{{{VMW_NS}}}qualifiers", "")
            label_el = prop.find(f"{{{OVF_NS}}}Label")
            label = label_el.text if label_el is not None else key
            desc_el = prop.find(f"{{{OVF_NS}}}Description")
            desc = desc_el.text if desc_el is not None else ""
            info.properties.append(OvfProperty(
                key=key, type=typ, default=default,
                user_configurable=user_configurable,
                label=label, description=desc,
                qualifiers=qualifiers,
            ))

    return info


def fetch_ovf_from_url(ovf_url: str) -> Optional[OvfInfo]:
    """
    Fetch and parse OVF info from a URL.

    Handles both .ovf files (fetched directly) and .ova files
    (fetched partially - only the OVF member is needed).
    """
    from urllib.parse import quote, urlunparse
    parsed = urlparse(ovf_url)
    # Percent-encode the path so special characters (spaces, backticks, etc.)
    # don't confuse the requests library into treating the URL as a file path.
    encoded_url = urlunparse(parsed._replace(path=quote(parsed.path, safe='/:@!$&\'()*+,;=')))
    filename = os.path.basename(parsed.path)

    try:
        if filename.endswith('.ovf'):
            response = requests.get(encoded_url, verify=False, timeout=30)
            response.raise_for_status()
            return parse_ovf(response.text)

        elif filename.endswith('.ova'):
            # OVA is a tar archive. Stream it, accumulating data until we can
            # successfully extract the .ovf member (typically the first entry).
            # We read up to 10MB which is more than enough for any OVF descriptor.
            response = requests.get(encoded_url, verify=False, stream=True, timeout=60)
            response.raise_for_status()

            buf = io.BytesIO()
            for chunk in response.iter_content(chunk_size=65536):
                buf.write(chunk)
                if buf.tell() >= 10 * 1024 * 1024:
                    break
            response.close()

            buf.seek(0)
            try:
                # mode='r|' = streaming tar; tolerates partial data at EOF
                with tarfile.open(fileobj=buf, mode='r|') as tar:
                    for member in tar:
                        if member.name.endswith('.ovf'):
                            f = tar.extractfile(member)
                            if f:
                                return parse_ovf(f.read().decode())
            except tarfile.TarError as e:
                print(f"  Warning: Could not read OVA tar: {e}")

    except Exception as e:
        print(f"  Warning: Could not fetch OVF from {ovf_url}: {e}")

    return None


def fetch_ovf_from_file(ova_path: str) -> Optional[OvfInfo]:
    """Parse OVF info from a local OVA or OVF file."""
    try:
        if ova_path.endswith('.ovf'):
            with open(ova_path) as f:
                return parse_ovf(f.read())
        elif ova_path.endswith('.ova'):
            with tarfile.open(ova_path) as tar:
                for member in tar.getmembers():
                    if member.name.endswith('.ovf'):
                        f = tar.extractfile(member)
                        if f:
                            return parse_ovf(f.read().decode())
    except Exception as e:
        print(f"  Warning: Could not parse OVF from {ova_path}: {e}")
    return None


class _VCenterSession(requests.Session):
    """
    requests.Session that automatically re-authenticates on 401 and retries
    the request once. This handles vCenter REST session expiry during long runs.
    """

    def __init__(self, client: "VCenterClient") -> None:
        super().__init__()
        self._vc_client = client
        self._refreshing = False

    def request(self, method, url, **kwargs):
        response = super().request(method, url, **kwargs)
        if response.status_code == 401 and not self._refreshing:
            # Session expired — re-authenticate and retry once.
            print("  REST session expired (401), re-authenticating...")
            self._refreshing = True
            try:
                self._vc_client._create_rest_session()
            finally:
                self._refreshing = False
            response = super().request(method, url, **kwargs)
        return response


class VCenterClient:
    """Client for vCenter operations using pyvmomi."""

    @staticmethod
    def _extract_error_message(response) -> str:
        """Extract human-readable error message from a vCenter REST API error response."""
        try:
            err_json = response.json()
            # Try to get default_message from messages array
            msgs = [m.get("default_message", "") for m in err_json.get("messages", []) if m.get("default_message")]
            if msgs:
                return " ".join(msgs)
            # Fallback to error_type
            if err_json.get("error_type"):
                return f"{err_json['error_type']}: {response.text[:200]}"
        except Exception:
            pass
        return response.text[:500] if response.text else response.reason

    def __init__(self, host: str, user: str, password: str, root_password: Optional[str] = None):
        self.host = host
        self.user = user
        self.password = password
        self.root_password = root_password or password
        self.si = None
        self.rest_session = None
        self.ssh = None

    def connect(self, ssh: bool = True) -> None:
        """Connect to vCenter."""
        print(f"Connecting to vCenter {self.host}...")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self.si = SmartConnect(
            host=self.host,
            user=self.user,
            pwd=self.password,
            sslContext=context
        )
        print("  Connected to vCenter via SOAP API")

        # Create REST session for Content Library operations
        self._create_rest_session()

        if ssh:
            self._create_ssh_session()

    def _create_rest_session(self) -> None:
        """Create REST API session for Content Library and vSphere API operations."""
        if self.rest_session is None:
            self.rest_session = _VCenterSession(self)
            self.rest_session.verify = False
        auth_url = f"https://{self.host}/api/session"
        response = self.rest_session.post(auth_url, auth=(self.user, self.password))
        response.raise_for_status()
        session_id = response.json()
        self.rest_session.headers.update({"vmware-api-session-id": session_id})
        print("  Connected to vCenter REST API")

    def _create_ssh_session(self) -> None:
        """Create SSH session to vCenter for Supervisor credential retrieval."""
        print(f"  Connecting to vCenter via SSH...")
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(
            hostname=self.host,
            username="root",
            password=self.root_password,
            look_for_keys=False,
            allow_agent=False
        )
        print("  Connected to vCenter via SSH")

    def disconnect(self) -> None:
        """Disconnect from vCenter."""
        # Delete REST API session to free up session slot
        if self.rest_session:
            try:
                self.rest_session.delete(f"https://{self.host}/api/session")
            except Exception:
                pass
            self.rest_session = None
        if self.ssh:
            self.ssh.close()
            self.ssh = None
        if self.si:
            Disconnect(self.si)
            self.si = None
            print("Disconnected from vCenter")

    def is_vm_powered_on(self, vm_name: str) -> bool:
        """
        Check whether a VM is powered on via the vSphere API.
        Searches all VMs in the inventory by name.
        Returns True if found and in poweredOn state.
        """
        content = self.si.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )
        try:
            for vm in container.view:
                if vm.name == vm_name:
                    return vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn
        finally:
            container.Destroy()
        return False

    def get_default_deploy_target(self,
                                   datacenter: Optional[str] = None,
                                   cluster: Optional[str] = None,
                                   datastore: Optional[str] = None,
                                   resource_pool: Optional[str] = None) -> dict:
        """
        Return a deploy target dict with resource_pool_id, folder_id, and datastore_id.

        Uses pyVmomi to traverse the inventory tree so it works across all
        vCenter versions (REST filter params vary by version).
        """
        content = self.si.RetrieveContent()

        # Find datacenter
        all_dcs = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.Datacenter], True
        )
        try:
            dc_list = list(all_dcs.view)
        finally:
            all_dcs.Destroy()

        if not dc_list:
            raise RuntimeError("No datacenters found in vCenter")
        if datacenter:
            dc_obj = next((d for d in dc_list if d.name == datacenter), None)
            if not dc_obj:
                raise RuntimeError(f"Datacenter '{datacenter}' not found")
        else:
            dc_obj = dc_list[0]
        print(f"  Using datacenter: {dc_obj.name}")

        # Find cluster within the datacenter's host folder
        def _find_clusters(folder):
            found = []
            for child in folder.childEntity:
                if isinstance(child, vim.ClusterComputeResource):
                    found.append(child)
                elif isinstance(child, vim.Folder):
                    found.extend(_find_clusters(child))
            return found

        clusters_in_dc = _find_clusters(dc_obj.hostFolder)
        if not clusters_in_dc:
            raise RuntimeError(f"No clusters found in datacenter '{dc_obj.name}'")
        if cluster:
            cl_obj = next((c for c in clusters_in_dc if c.name == cluster), None)
            if not cl_obj:
                raise RuntimeError(f"Cluster '{cluster}' not found")
        else:
            cl_obj = clusters_in_dc[0]
        print(f"  Using cluster: {cl_obj.name}")

        # Resolve resource pool: explicit name > cluster root RP.
        def _print_rp_tree(pool, prefix=""):
            print(f"  {prefix}{pool.name} ({pool._moId})")
            for child in pool.resourcePool:
                _print_rp_tree(child, prefix + "  ")

        print(f"  Resource pool tree for cluster '{cl_obj.name}':")
        _print_rp_tree(cl_obj.resourcePool)

        if resource_pool:
            def _find_rp(pool, name):
                if pool.name == name:
                    return pool
                for child in pool.resourcePool:
                    found = _find_rp(child, name)
                    if found:
                        return found
                return None
            rp_obj = _find_rp(cl_obj.resourcePool, resource_pool)
            if not rp_obj:
                raise RuntimeError(f"Resource pool '{resource_pool}' not found in cluster '{cl_obj.name}'")
        else:
            rp_obj = cl_obj.resourcePool
            if not rp_obj:
                raise RuntimeError(f"No resource pool found for cluster '{cl_obj.name}'")
        rp_id = rp_obj._moId
        print(f"  Using resource pool: {rp_obj.name} ({rp_id})")

        # VM folder of the datacenter
        folder_id = dc_obj.vmFolder._moId
        print(f"  Using VM folder: {folder_id}")

        # Find a suitable datastore accessible from the cluster
        ds_candidates = list(cl_obj.datastore)
        if not ds_candidates:
            raise RuntimeError(f"No datastores found for cluster '{cl_obj.name}'")
        if datastore:
            ds_obj = next((d for d in ds_candidates if d.name == datastore), None)
            if not ds_obj:
                raise RuntimeError(f"Datastore '{datastore}' not found")
        else:
            # Prefer accessible, non-vSAN datastores
            writable = [
                d for d in ds_candidates
                if d.summary.accessible
                and d.summary.type not in ("vsan", "VSAN", "vVol")
            ]
            ds_obj = writable[0] if writable else ds_candidates[0]
        ds_id = ds_obj._moId
        print(f"  Using datastore: {ds_obj.name} ({ds_id})")

        return {
            "resource_pool_id": rp_id,
            "folder_id": folder_id,
            "datastore_id": ds_id,
        }

    def _filter_library_item(self, item_id: str, resource_pool_id: str) -> dict:
        """
        Call the OVF filter action to get deployment requirements (storage groups,
        network mappings, etc.) for a library item against a given target.
        Returns the filter result dict, or {} on failure.
        """
        url = f"https://{self.host}/api/vcenter/ovf/library-item/{item_id}?action=filter"
        body = {"target": {"resource_pool_id": resource_pool_id}}
        response = self.rest_session.post(url, json=body)
        if response.ok:
            return response.json()
        return {}

    def deploy_library_item(self, item_id: str, vm_name: str,
                             resource_pool_id: str, folder_id: str,
                             datastore_id: str) -> tuple[str, str]:
        """
        Deploy a content library item using the vSphere REST API.
        Returns (resource_id, resource_type) where resource_type is
        'VirtualMachine' or 'VirtualApp'.
        """
        # Discover storage groups so we can map them all to the default datastore.
        # The filter API returns storage_groups as a list of string IDs matching
        # vmw:StorageGroupSection vmw:id values in the OVF descriptor.
        ovf_summary = self._filter_library_item(item_id, resource_pool_id)
        storage_group_ids = [sg for sg in ovf_summary.get("storage_groups", [])
                             if isinstance(sg, str)]
        storage_mappings = {
            sg_id: {
                "type": "DATASTORE",
                "datastore_id": datastore_id,
                "provisioning": "thin",
            }
            for sg_id in storage_group_ids
        }
        if storage_mappings:
            print(f"  Mapping storage groups to default datastore: {list(storage_mappings)}")

        # If the OVF has IpAllocationParams and supports DHCP, request DHCP so
        # vCenter does not require an IP pool on the target network to power on.
        additional_parameters = []
        for param in ovf_summary.get("additional_params", []):
            if param.get("type") == "IpAllocationParams":
                supported = param.get("supported_ip_allocation_policy", [])
                if "DHCP" in supported:
                    ip_param = dict(param)
                    ip_param["ip_allocation_policy"] = "DHCP"
                    additional_parameters.append(ip_param)
                    print("  Overriding IP allocation policy to DHCP")

            elif param.get("type") == "PropertyParams":
                # Auto-fill OVF properties so vCenter can power on the VM.
                # Properties that are left empty for mandatory fields cause a
                # power-on failure ("Property X must be configured").
                props = param.get("properties", [])
                if props:
                    filled = []
                    for p in props:
                        ovf_prop = OvfProperty(
                            key=p.get("id", ""),
                            type=p.get("type", "string"),
                            default=p.get("value", ""),
                            user_configurable=not p.get("ui_optional", True),
                            label=p.get("label", ""),
                            description=p.get("description", ""),
                        )
                        value = _smart_value_for_property(ovf_prop, for_vcenter=True)
                        filled.append(dict(p, value=value))
                    additional_parameters.append({"type": "PropertyParams", "properties": filled})
                    print(f"  Auto-filled {len(filled)} OVF property/properties for deploy")

        url = f"https://{self.host}/api/vcenter/ovf/library-item/{item_id}?action=deploy"
        deployment_spec: dict = {
            "name": vm_name,
            "accept_all_EULA": True,
            "storage_provisioning": "thin",
            "default_datastore_id": datastore_id,
        }
        if storage_mappings:
            deployment_spec["storage_mappings"] = storage_mappings
        if additional_parameters:
            deployment_spec["additional_parameters"] = additional_parameters
        body = {
            "target": {
                "resource_pool_id": resource_pool_id,
                "folder_id": folder_id,
            },
            "deployment_spec": deployment_spec,
        }
        # Deploy can take a while for large OVFs; retry once on 504 or read timeout.
        import requests as _requests
        for attempt in range(2):
            try:
                response = self.rest_session.post(url, json=body, timeout=600)
            except _requests.exceptions.ReadTimeout:
                if attempt == 0:
                    print("  Deploy read timed out, retrying...")
                    continue
                raise RuntimeError("Deploy timed out after two attempts (read timeout=600s)")
            if response.status_code != 504:
                break
            if attempt == 0:
                print("  Deploy timed out (504), retrying...")
        if not response.ok:
            raise RuntimeError(
                f"Failed to deploy library item: "
                f"{response.status_code} {response.reason} {response.text}"
            )
        result = response.json()
        if not result.get("succeeded"):
            # Extract the most useful error/warning messages from the vCenter response.
            msgs = []
            error_block = result.get("error") or {}
            for err in error_block.get("errors", []):
                inner = err.get("error", {})
                for m in inner.get("messages", []):
                    msgs.append(m.get("default_message", ""))
            for warn in error_block.get("warnings", []):
                for issue in warn.get("issues", []):
                    msgs.append(issue.get("message", {}).get("default_message", ""))
            reason = "; ".join(m for m in msgs if m) or str(result)
            raise RuntimeError(f"Deploy failed: {reason}")
        resource_id = result.get("resource_id", {}).get("id")
        resource_type = result.get("resource_id", {}).get("type", "VirtualMachine")
        if not resource_id:
            raise RuntimeError(f"Deploy returned no resource ID: {result}")
        print(f"  Deployed {resource_type} '{vm_name}' with ID: {resource_id}")
        return resource_id, resource_type

    def power_on_vm_by_id(self, vm_id: str) -> None:
        """Power on a VM by its vSphere VM ID."""
        url = f"https://{self.host}/api/vcenter/vm/{vm_id}/power?action=start"
        response = self.rest_session.post(url)
        if not response.ok:
            # 400 means already powered on — not an error.
            if response.status_code == 400:
                return
            # Extract the most useful message from the JSON error body.
            reason = response.text
            try:
                err = response.json()
                msgs = [m.get("default_message", "")
                        for m in err.get("messages", [])
                        if m.get("default_message")]
                if msgs:
                    reason = " ".join(msgs)
            except Exception:
                pass
            raise RuntimeError(
                f"Failed to power on VM {vm_id}: "
                f"{response.status_code} {response.reason} {reason}"
            )

    def wait_for_vm_powered_on_by_id(self, vm_id: str,
                                      timeout: int = VM_TOOLS_WAIT_TIMEOUT) -> bool:
        """
        Poll VM power state by VM ID via REST API until powered on or timeout.
        Returns True if powered on within timeout.
        """
        url = f"https://{self.host}/api/vcenter/vm/{vm_id}/power"
        start = time.time()
        while time.time() - start < timeout:
            r = self.rest_session.get(url)
            if r.ok and r.json().get("state") == "POWERED_ON":
                return True
            time.sleep(POLL_INTERVAL)
        return False

    def delete_vm_by_id(self, vm_id: str) -> None:
        """Power off and delete a VM by its vSphere VM ID (best-effort)."""
        try:
            self.rest_session.post(
                f"https://{self.host}/api/vcenter/vm/{vm_id}/power?action=stop&force=true"
            )
        except Exception:
            pass
        try:
            r = self.rest_session.delete(f"https://{self.host}/api/vcenter/vm/{vm_id}")
            if r.ok:
                print(f"  Deleted VM {vm_id}")
        except Exception as e:
            print(f"  Warning: could not delete VM {vm_id}: {e}")

    def delete_existing_by_name(self, name: str) -> None:
        """Delete any VM or vApp with the given name (best-effort pre-deploy cleanup).

        Raises RuntimeError if a matching object was found but could not be deleted,
        so the caller does not proceed to deploy and hit a name collision.
        """
        from pyVmomi import vim as _vim
        from pyVim.task import WaitForTask
        content = self.si.RetrieveContent()
        for obj_type in (_vim.VirtualApp, _vim.VirtualMachine):
            view = content.viewManager.CreateContainerView(
                content.rootFolder, [obj_type], True
            )
            try:
                matches = [o for o in view.view if o.name == name]
            finally:
                view.Destroy()
            for obj in matches:
                print(f"  Pre-deploy cleanup: deleting existing {obj_type.__name__} '{name}' ({obj._moId})")
                # Power off only if currently running — avoids errors on already-off objects.
                try:
                    if isinstance(obj, _vim.VirtualApp):
                        if obj.summary.vAppState != "stopped":
                            WaitForTask(obj.PowerOff(force=True))
                    else:
                        if obj.runtime.powerState != _vim.VirtualMachinePowerState.poweredOff:
                            WaitForTask(obj.PowerOff(force=True))
                except Exception as e:
                    print(f"  Warning: could not power off '{name}': {e}")
                try:
                    WaitForTask(obj.Destroy())
                    print(f"  Pre-deploy cleanup: deleted '{name}'")
                except Exception as e:
                    # Already gone — another worker or vCenter cleaned it up
                    if "ManagedObjectNotFound" in type(e).__name__ or "has already been deleted" in str(e):
                        print(f"  Pre-deploy cleanup: '{name}' already gone, skipping")
                        continue
                    raise RuntimeError(
                        f"Pre-deploy cleanup: could not delete existing {obj_type.__name__} "
                        f"'{name}' ({obj._moId}): {e}"
                    ) from e

    def power_on_vapp_by_id(self, vapp_id: str) -> None:
        """Power on a vApp by its MoRef ID using the SOAP API."""
        from pyVmomi import vim as _vim, vmodl as _vmodl
        from pyVim.task import WaitForTask
        vapp = _vim.VirtualApp(vapp_id)
        vapp._stub = self.si._stub
        try:
            task = vapp.PowerOn()
            WaitForTask(task)
        except _vim.fault.MissingIpPool as e:
            raise RuntimeError(
                f"vApp power-on requires an IP pool on network '{e.value}' "
                f"(property '{e.id}'). Assign an IP pool to that network in vCenter."
            ) from e
        except _vmodl.fault.ManagedObjectNotFound:
            raise RuntimeError(f"vApp {vapp_id} not found — may have been deleted by a concurrent operation")

    def wait_for_vapp_powered_on_by_id(self, vapp_id: str,
                                        timeout: int = VM_TOOLS_WAIT_TIMEOUT) -> bool:
        """Poll vApp power state via SOAP until powered on or timeout."""
        from pyVmomi import vim as _vim, vmodl as _vmodl
        vapp = _vim.VirtualApp(vapp_id)
        vapp._stub = self.si._stub
        start = time.time()
        while time.time() - start < timeout:
            try:
                if vapp.summary.vAppState == "started":
                    return True
            except _vmodl.fault.ManagedObjectNotFound:
                return False
            time.sleep(POLL_INTERVAL)
        return False

    def delete_vapp_by_id(self, vapp_id: str) -> None:
        """Power off and delete a vApp by its MoRef ID using the SOAP API (best-effort)."""
        from pyVmomi import vim as _vim
        from pyVim.task import WaitForTask
        vapp = _vim.VirtualApp(vapp_id)
        vapp._stub = self.si._stub
        try:
            task = vapp.PowerOff(force=True)
            WaitForTask(task)
        except Exception:
            pass
        try:
            task = vapp.Destroy()
            WaitForTask(task)
            print(f"  Deleted vApp {vapp_id}")
        except Exception as e:
            print(f"  Warning: could not delete vApp {vapp_id}: {e}")

    def get_supervisor_credentials(self) -> tuple[str, str]:
        """
        Get Supervisor IP and password from vCenter.

        Uses /usr/lib/vmware-wcp/decryptK8Pwd.py which outputs both
        the Supervisor IP and the root password for SSH access.

        Returns:
            Tuple of (supervisor_ip, supervisor_password)
        """
        print("Retrieving Supervisor credentials from vCenter...")

        # Use decryptK8Pwd.py which provides Supervisor (K8s control plane) credentials
        stdin, stdout, stderr = self.ssh.exec_command(
            "/usr/lib/vmware-wcp/decryptK8Pwd.py"
        )
        output = stdout.read().decode()
        exit_code = stdout.channel.recv_exit_status()

        if exit_code == 0 and output:
            # Parse the output - format is typically:
            # IP: x.x.x.x
            # PWD: password
            lines = output.strip().split('\n')
            sv_ip = None
            sv_pwd = None

            for line in lines:
                line = line.strip()
                if line.startswith('IP:'):
                    sv_ip = line.split(':', 1)[1].strip()
                elif line.startswith('PWD:'):
                    sv_pwd = line.split(':', 1)[1].strip()

            if sv_ip and sv_pwd:
                print(f"  Found Supervisor IP: {sv_ip}")
                print(f"  Found Supervisor password: {'*' * len(sv_pwd)}")
                return sv_ip, sv_pwd

        # If decryptK8Pwd.py didn't work, try to get IP from API and use provided password
        sv_ip = self._get_supervisor_ip_from_api()
        if sv_ip:
            print(f"  Found Supervisor IP from API: {sv_ip}")
            print("  WARNING: Could not retrieve Supervisor password automatically.")
            print("           Use --supervisor-root-password to provide it.")
            raise RuntimeError(
                "Could not retrieve Supervisor password. "
                "Please provide --supervisor-root-password"
            )

        raise RuntimeError(
            "Could not retrieve Supervisor credentials from vCenter. "
            "Make sure WCP is enabled and /usr/lib/vmware-wcp/decryptK8Pwd.py is available."
        )

    def _get_supervisor_ip_from_api(self) -> Optional[str]:
        """Get Supervisor control plane IP from vSphere API."""
        # Try to get from WCP cluster configuration
        stdin, stdout, stderr = self.ssh.exec_command(
            "grep -r 'control-plane' /etc/vmware-wcp/ 2>/dev/null | head -1 || "
            "cat /etc/vmware-wcp/wcpsvc.yaml 2>/dev/null | grep -i 'address' | head -1"
        )
        output = stdout.read().decode().strip()

        # Try to extract IP from output
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        match = ip_pattern.search(output)
        if match:
            return match.group(1)

        # Try REST API to get namespaces/clusters info
        try:
            url = f"https://{self.host}/api/vcenter/namespace-management/clusters"
            response = self.rest_session.get(url)
            if response.status_code == 200:
                clusters = response.json()
                for cluster in clusters:
                    cluster_id = cluster.get("cluster")
                    if cluster_id:
                        detail_url = f"https://{self.host}/api/vcenter/namespace-management/clusters/{cluster_id}"
                        detail_response = self.rest_session.get(detail_url)
                        if detail_response.status_code == 200:
                            detail = detail_response.json()
                            api_server = detail.get("api_server_cluster_endpoint")
                            if api_server:
                                return api_server
        except Exception as e:
            print(f"  Warning: Could not get Supervisor IP from API: {e}")

        return None

    # ------------------------------------------------------------------ #
    # Infrastructure setup helpers (used by cmd_setup_infra)             #
    # ------------------------------------------------------------------ #

    def _pbm_bearer_token(self) -> str:
        """
        Return the REST API session token used as a Bearer token for PBM SOAP calls.
        On vCenter 9.x, PBM SOAP requires Authorization: Bearer <rest-token>.
        """
        return self.rest_session.headers.get("vmware-api-session-id", "")

    def _pbm_soap(self, body: str) -> str:
        """
        Execute a PBM SOAP call using the REST session token for authentication.
        Returns the raw response text. Raises RuntimeError on HTTP error.
        """
        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soapenv:Envelope'
            ' xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"'
            ' xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            ' xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
            f'<soapenv:Body>{body}</soapenv:Body>'
            '</soapenv:Envelope>'
        )
        resp = self.rest_session.post(
            f"https://{self.host}/pbm/sdk",
            data=envelope.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=UTF-8",
                "SOAPAction": "urn:pbm/2.0",
                "Authorization": f"Bearer {self._pbm_bearer_token()}",
            },
        )
        if resp.status_code not in (200, 500):
            raise RuntimeError(
                f"PBM SOAP call failed: {resp.status_code} {resp.text[:200]}"
            )
        if resp.status_code == 500 and "SecurityError" in resp.text:
            raise RuntimeError("PBM authentication failed (SecurityError)")
        return resp.text

    def ensure_tag_category(self, name: str, cardinality: str = "SINGLE") -> str:
        """
        Return the ID of the tag category with the given name, creating it if absent.
        cardinality: 'SINGLE' or 'MULTIPLE'.
        On vCenter 9.x the tagging API is at /api/cis/tagging/category (not tag-category).
        """
        list_url = f"https://{self.host}/api/cis/tagging/category"
        resp = self.rest_session.get(list_url)
        resp.raise_for_status()
        for cat_id in resp.json():
            detail = self.rest_session.get(f"{list_url}/{cat_id}")
            detail.raise_for_status()
            if detail.json().get("name") == name:
                print(f"  Tag category '{name}' already exists ({cat_id})")
                return cat_id

        # vCenter 9.x: flat body (no create_spec wrapper)
        body = {
            "name": name,
            "description": "",
            "cardinality": cardinality,
            "associable_types": [],
        }
        resp = self.rest_session.post(list_url, json=body)
        if not resp.ok:
            raise RuntimeError(
                f"Failed to create tag category '{name}': {resp.status_code} {resp.text}"
            )
        cat_id = resp.json()
        print(f"  Created tag category '{name}' ({cat_id})")
        return cat_id

    def ensure_tag(self, category_id: str, name: str) -> str:
        """Return the ID of the tag with the given name in the category, creating it if absent."""
        list_url = f"https://{self.host}/api/cis/tagging/tag"
        resp = self.rest_session.get(list_url)
        resp.raise_for_status()
        for tag_id in resp.json():
            detail = self.rest_session.get(f"{list_url}/{tag_id}")
            detail.raise_for_status()
            d = detail.json()
            if d.get("name") == name and d.get("category_id") == category_id:
                print(f"  Tag '{name}' already exists ({tag_id})")
                return tag_id

        # vCenter 9.x: flat body (no create_spec wrapper)
        body = {
            "name": name,
            "description": "",
            "category_id": category_id,
        }
        resp = self.rest_session.post(list_url, json=body)
        if not resp.ok:
            raise RuntimeError(
                f"Failed to create tag '{name}': {resp.status_code} {resp.text}"
            )
        tag_id = resp.json()
        print(f"  Created tag '{name}' ({tag_id})")
        return tag_id

    def attach_tag(self, tag_id: str, obj_type: str, obj_id: str) -> None:
        """
        Attach a tag to a managed object (idempotent).
        On vCenter 9.x the path is /api/cis/tagging/tag-association/{tag_id}?action=attach
        with body {"object_id": {"id": ..., "type": ...}}.
        """
        import urllib.parse as _urlparse
        encoded_tag_id = _urlparse.quote(tag_id, safe="")
        url = f"https://{self.host}/api/cis/tagging/tag-association/{encoded_tag_id}?action=attach"
        body = {"object_id": {"id": obj_id, "type": obj_type}}
        resp = self.rest_session.post(url, json=body)
        if resp.status_code == 204:
            print(f"  Attached tag to {obj_type} {obj_id}")
            return
        if not resp.ok:
            # 403 with "already" means already attached — tolerate it
            if resp.status_code in (400, 403) and "already" in resp.text.lower():
                print(f"  Tag already attached to {obj_type} {obj_id}")
                return
            raise RuntimeError(
                f"Failed to attach tag {tag_id} to {obj_type} {obj_id}: "
                f"{resp.status_code} {resp.text}"
            )
        print(f"  Attached tag to {obj_type} {obj_id}")

    def ensure_nfs_datastore(self, cluster_name: str, nfs_host: str,
                              remote_path: str, ds_name: str) -> str:
        """
        Mount an NFS datastore on every host in the named cluster.
        Returns the datastore MoRef ID.
        If the datastore already exists, returns its ID without remounting.
        Uses NFSv4.1 with DEFAULT_INFRA_NFS_CONNECTIONS TCP connections.
        """
        from pyVmomi import vim as _vim

        content = self.si.RetrieveContent()

        # Find cluster
        view = content.viewManager.CreateContainerView(
            content.rootFolder, [_vim.ClusterComputeResource], True
        )
        try:
            clusters = list(view.view)
        finally:
            view.Destroy()

        cluster = next((c for c in clusters if c.name == cluster_name), None)
        if cluster is None:
            raise RuntimeError(f"Cluster '{cluster_name}' not found")

        # Check if datastore already exists
        ds_view = content.viewManager.CreateContainerView(
            content.rootFolder, [_vim.Datastore], True
        )
        try:
            existing_ds = next((d for d in ds_view.view if d.name == ds_name), None)
        finally:
            ds_view.Destroy()

        if existing_ds is not None:
            ds_id = existing_ds._moId
            print(f"  NFS datastore '{ds_name}' already exists ({ds_id})")
            return ds_id

        # Mount on each host in the cluster
        spec = _vim.host.NasVolume.Specification(
            remoteHost=nfs_host,
            remotePath=remote_path,
            localPath=ds_name,
            accessMode="readWrite",
            type=DEFAULT_INFRA_NFS_TYPE,
            connections=DEFAULT_INFRA_NFS_CONNECTIONS,
        )

        ds_id = None
        for host in cluster.host:
            print(f"  Mounting NFS datastore '{ds_name}' on host {host.name}...")
            try:
                ds = host.configManager.datastoreSystem.CreateNasDatastore(spec)
                if ds_id is None:
                    ds_id = ds._moId
                print(f"    Mounted on {host.name}")
            except _vim.fault.DuplicateName:
                print(f"    Already mounted on {host.name}")
                for d in host.datastore:
                    if d.name == ds_name and ds_id is None:
                        ds_id = d._moId
            except Exception as e:
                print(f"    Warning: could not mount on {host.name}: {e}")

        if ds_id is None:
            # Last resort: search again after mounting attempts
            ds_view2 = content.viewManager.CreateContainerView(
                content.rootFolder, [_vim.Datastore], True
            )
            try:
                found = next((d for d in ds_view2.view if d.name == ds_name), None)
            finally:
                ds_view2.Destroy()
            if found:
                ds_id = found._moId
            else:
                raise RuntimeError(
                    f"NFS datastore '{ds_name}' could not be mounted on any host"
                )

        print(f"  NFS datastore '{ds_name}' ready ({ds_id})")
        return ds_id

    def ensure_storage_policy(self, policy_name: str, tag_category_name: str,
                               tag_name: str) -> str:
        """
        Create a VM storage policy that selects datastores tagged with the given tag.
        Returns the policy ID. If a policy with the same name already exists, returns its ID.

        Uses PBM SOAP (the only supported creation path) authenticated via the REST
        session token as a Bearer token (required on vCenter 9.x).
        """
        # Check if policy already exists via REST (list only)
        list_url = f"https://{self.host}/api/vcenter/storage/policies"
        resp = self.rest_session.get(list_url)
        resp.raise_for_status()
        for p in resp.json():
            if p.get("name") == policy_name:
                pid = p.get("policy")
                print(f"  Storage policy '{policy_name}' already exists ({pid})")
                return pid

        # Build PBM SOAP create call.
        # The tag-based capability uses namespace http://www.vmware.com/storage/tag
        # and capability ID equal to the tag category name.
        prop_id = f"com.vmware.storage.tag.{tag_category_name}.property"
        soap_body = (
            f'<PbmCreate xmlns="urn:pbm">'
            f'<_this versionId="2.0" type="PbmProfileProfileManager">ProfileManager</_this>'
            f'<createSpec xsi:type="pbm:PbmCapabilityProfileCreateSpec">'
            f'<name>{policy_name}</name>'
            f'<description>Tag-based policy selecting datastores tagged {tag_name!r}</description>'
            f'<resourceType><resourceType>STORAGE</resourceType></resourceType>'
            f'<constraints xsi:type="pbm:PbmCapabilitySubProfileConstraints">'
            f'<subProfiles>'
            f'<name>Tag based placement</name>'
            f'<capability>'
            f'<id>'
            f'<namespace>http://www.vmware.com/storage/tag</namespace>'
            f'<id>{tag_category_name}</id>'
            f'</id>'
            f'<constraint>'
            f'<propertyInstance>'
            f'<id>{prop_id}</id>'
            f'<value xsi:type="pbm:PbmCapabilityDiscreteSet">'
            f'<values xsi:type="xsd:string">{tag_name}</values>'
            f'</value>'
            f'</propertyInstance>'
            f'</constraint>'
            f'</capability>'
            f'</subProfiles>'
            f'</constraints>'
            f'</createSpec>'
            f'</PbmCreate>'
        )
        resp_text = self._pbm_soap(soap_body)
        if "Fault" in resp_text:
            raise RuntimeError(
                f"PBM failed to create storage policy '{policy_name}': {resp_text[:400]}"
            )

        # Extract the new policy ID from the response
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(resp_text)
        uid_el = root.find(".//{urn:pbm}uniqueId")
        if uid_el is None:
            uid_el = root.find(".//{urn:pbm}returnval/{urn:pbm}uniqueId")
        if uid_el is None:
            # Try without namespace
            uid_el = root.find(".//uniqueId")
        pid = uid_el.text if uid_el is not None else "unknown"
        print(f"  Created storage policy '{policy_name}' ({pid})")
        return pid

    def ensure_local_content_library(self, name: str, datastore_id: str) -> str:
        """
        Create a local content library backed by the given datastore.
        Returns the library ID. If a library with the same name already exists, returns its ID.
        """
        existing = self.find_content_library(name)
        if existing:
            return existing

        body = {
            "name": name,
            "description": "OVF test content library",
            "type": "LOCAL",
            "storage_backings": [
                {
                    "type": "DATASTORE",
                    "datastore_id": datastore_id,
                }
            ],
        }
        url = f"https://{self.host}/api/content/local-library"
        resp = self.rest_session.post(url, json=body)
        if not resp.ok:
            raise RuntimeError(
                f"Failed to create content library '{name}': {resp.status_code} {resp.text}"
            )
        lib_id = resp.json()
        print(f"  Created content library '{name}' ({lib_id})")
        return lib_id

    def set_content_library_max_concurrent_syncs(self, max_syncs: int) -> None:
        """
        Set the global 'Library Maximum Concurrent Sync Items' vCenter configuration.
        Controls how many library items can be concurrently synchronized to a subscriber.
        """
        url = f"https://{self.host}/api/content/configuration"
        body = {"maximum_concurrent_item_syncs": max_syncs}
        resp = self.rest_session.patch(url, json=body)
        if not resp.ok:
            raise RuntimeError(
                f"Failed to set content library max concurrent syncs: {resp.status_code} {resp.text}"
            )
        print(f"  Content library max concurrent sync items set to {max_syncs}")

    def ensure_supervisor_namespace(self, namespace: str, cluster_id: str,
                                     storage_policy_id: str, vm_class_name: str,
                                     library_id: str) -> None:
        """
        Create a Supervisor namespace with the given storage policy, VM class, and
        content library assigned. Idempotent — updates assignments if namespace exists.

        On vCenter 9.x, content_libraries in vm_service_spec is a list of string IDs.
        """
        ns_url = f"https://{self.host}/api/vcenter/namespaces/instances/{namespace}"
        resp = self.rest_session.get(ns_url)

        if resp.status_code == 404:
            body = {
                "namespace": namespace,
                "cluster": cluster_id,
                "storage_specs": [{"policy": storage_policy_id}],
                "vm_service_spec": {
                    "vm_classes": [vm_class_name],
                    "content_libraries": [library_id],
                },
            }
            create_url = f"https://{self.host}/api/vcenter/namespaces/instances"
            r = self.rest_session.post(create_url, json=body)
            if not r.ok:
                raise RuntimeError(
                    f"Failed to create namespace '{namespace}': {r.status_code} {r.text}"
                )
            print(f"  Created namespace '{namespace}'")
        elif resp.ok:
            existing = resp.json()
            # Check if everything is already assigned correctly
            existing_policies = {s.get("policy") for s in existing.get("storage_specs", [])}
            existing_classes = set(existing.get("vm_service_spec", {}).get("vm_classes", []))
            existing_libs = set(existing.get("vm_service_spec", {}).get("content_libraries", []))

            needs_update = (
                storage_policy_id not in existing_policies
                or vm_class_name not in existing_classes
                or library_id not in existing_libs
            )
            if not needs_update:
                print(f"  Namespace '{namespace}' already has all required assignments")
                return

            print(f"  Namespace '{namespace}' exists — updating assignments")
            # Merge: keep existing assignments and add ours
            all_policies = list(existing_policies | {storage_policy_id})
            all_classes = sorted(existing_classes | {vm_class_name})
            all_libs = sorted(existing_libs | {library_id})

            patch_body = {
                "storage_specs": [{"policy": p} for p in all_policies],
                "vm_service_spec": {
                    "vm_classes": all_classes,
                    "content_libraries": all_libs,
                },
            }
            r = self.rest_session.patch(ns_url, json=patch_body)
            if not r.ok:
                raise RuntimeError(
                    f"Failed to update namespace '{namespace}': {r.status_code} {r.text}"
                )
            print(f"  Updated namespace '{namespace}' assignments")
        else:
            raise RuntimeError(
                f"Failed to query namespace '{namespace}': {resp.status_code} {resp.text}"
            )

    def get_supervisor_cluster_id(self, cluster_name: str) -> str:
        """Return the vSphere cluster MoRef ID for the named cluster."""
        from pyVmomi import vim as _vim
        content = self.si.RetrieveContent()
        view = content.viewManager.CreateContainerView(
            content.rootFolder, [_vim.ClusterComputeResource], True
        )
        try:
            clusters = list(view.view)
        finally:
            view.Destroy()
        cluster = next((c for c in clusters if c.name == cluster_name), None)
        if cluster is None:
            raise RuntimeError(f"Cluster '{cluster_name}' not found")
        return cluster._moId

    def get_default_datastore_id(self, cluster_name: str) -> str:
        """Return the MoRef ID of the first accessible non-vSAN datastore in the cluster."""
        from pyVmomi import vim as _vim
        content = self.si.RetrieveContent()
        view = content.viewManager.CreateContainerView(
            content.rootFolder, [_vim.ClusterComputeResource], True
        )
        try:
            clusters = list(view.view)
        finally:
            view.Destroy()
        cluster = next((c for c in clusters if c.name == cluster_name), None)
        if cluster is None:
            raise RuntimeError(f"Cluster '{cluster_name}' not found")
        candidates = [
            d for d in cluster.datastore
            if d.summary.accessible and d.summary.type not in ("vsan", "VSAN", "vVol")
        ]
        if not candidates:
            raise RuntimeError(f"No accessible non-vSAN datastore found in cluster '{cluster_name}'")
        return candidates[0]._moId

    def find_content_library(self, name: str) -> Optional[str]:
        """Find a content library by name and return its ID."""
        url = f"https://{self.host}/api/content/library"

        # Retry on 503 Service Unavailable
        for attempt in range(5):
            response = self.rest_session.get(url)
            if response.status_code != 503:
                break
            error_msg = self._extract_error_message(response)
            wait = 5 * (attempt + 1)
            print(f"  Content library service unavailable (503): {error_msg[:100]}... retrying in {wait}s")
            time.sleep(wait)
        if not response.ok:
            error_msg = self._extract_error_message(response)
            raise RuntimeError(f"Content library API failed: {response.status_code} — {error_msg}")

        library_ids = response.json()
        for lib_id in library_ids:
            lib_url = f"https://{self.host}/api/content/library/{lib_id}"
            lib_response = self.rest_session.get(lib_url)
            if lib_response.status_code == 503:
                # Retry once for individual library fetch
                time.sleep(5)
                lib_response = self.rest_session.get(lib_url)
            lib_response.raise_for_status()
            lib_info = lib_response.json()
            if lib_info.get("name") == name:
                print(f"  Found content library '{name}' with ID: {lib_id}")
                return lib_id

        return None

    def find_library_item(self, library_id: str, item_name: str) -> Optional[dict]:
        """
        Find a library item by name in a library.
        Returns a dict with 'id' and 'size' keys, or None if not found.
        """
        # Use the find action with POST body for efficient server-side filtering
        find_url = f"https://{self.host}/api/content/library/item?action=find"
        find_spec = {
            "name": item_name,
            "library_id": library_id,
        }

        # Retry on 503 Service Unavailable
        for attempt in range(5):
            response = self.rest_session.post(find_url, json=find_spec)
            if response.status_code != 503:
                break
            error_msg = self._extract_error_message(response)
            wait = 5 * (attempt + 1)
            print(f"  Content library service unavailable (503): {error_msg[:100]}... retrying in {wait}s")
            time.sleep(wait)
        if not response.ok:
            error_msg = self._extract_error_message(response)
            raise RuntimeError(f"Content library find failed: {response.status_code} — {error_msg}")

        item_ids = response.json()
        if not item_ids:
            return None

        # Fetch details for the first matching item to get size
        item_id = item_ids[0]
        item_url = f"https://{self.host}/api/content/library/item/{item_id}"

        for attempt in range(3):
            item_response = self.rest_session.get(item_url)
            if item_response.status_code != 503:
                break
            time.sleep(5)

        if item_response.status_code == 404:
            return None
        item_response.raise_for_status()
        item_info = item_response.json()
        return {"id": item_id, "size": item_info.get("size", 0)}

    def delete_library_item(self, item_id: str) -> None:
        """Delete a content library item by ID."""
        url = f"https://{self.host}/api/content/library/item/{item_id}"
        response = self.rest_session.delete(url)
        if not response.ok:
            raise RuntimeError(
                f"Failed to delete library item {item_id}: "
                f"{response.status_code} {response.reason}\n{response.text}"
            )
        print(f"  Deleted incomplete library item {item_id}")

    def cancel_stale_sessions(self, library_id: str) -> None:
        """
        Cancel any ACTIVE update sessions for items in the given library.

        Stale sessions from previous crashed/timed-out runs hold vpxd resources
        and cause 503 errors on subsequent item creation requests. Call this
        once at startup before beginning uploads.
        """
        list_url = f"https://{self.host}/api/content/library/item/update-session"
        response = self.rest_session.get(list_url, timeout=30)
        if not response.ok:
            print(f"  Warning: could not list update sessions: {response.status_code} {response.text[:100]}")
            return

        session_ids = response.json()
        if not session_ids:
            return

        cancelled = 0
        for sid in session_ids:
            # Fetch session details to check library and state
            detail_url = f"https://{self.host}/api/content/library/item/update-session/{sid}"
            detail = self.rest_session.get(detail_url, timeout=30)
            if not detail.ok:
                continue
            info = detail.json()
            if info.get("state") != "ACTIVE":
                continue
            # Only cancel sessions belonging to our library
            item_id = info.get("library_item_id", "")
            item_url = f"https://{self.host}/api/content/library/item/{item_id}"
            item_resp = self.rest_session.get(item_url, timeout=30)
            if not item_resp.ok:
                continue
            if item_resp.json().get("library_id") != library_id:
                continue
            cancel_url = f"https://{self.host}/api/content/library/item/update-session/{sid}?action=cancel"
            cancel_resp = self.rest_session.post(cancel_url, timeout=30)
            if cancel_resp.ok:
                print(f"  Cancelled stale update session {sid}")
                cancelled += 1
            else:
                print(f"  Warning: could not cancel session {sid}: {cancel_resp.status_code}")

        if cancelled:
            print(f"  Cancelled {cancelled} stale session(s) — waiting 5s for vpxd to clean up...")
            time.sleep(5)

    def upload_ovf(self, library_id: str, source: str, item_name: str) -> str:
        """
        Upload an OVF/OVA to the content library from a URL or local file path.
        If an item with the same name exists but has 0 bytes (failed prior upload),
        it is deleted and re-uploaded.
        
        For untrusted certificates: attempts to add the cert to vCenter's trust
        store once, then retries. If that also fails, raises UntrustedSourceError.
        """
        print(f"Uploading OVF '{item_name}' from {source} to content library...")

        # Check if item already exists
        existing_item = self.find_library_item(library_id, item_name)
        if existing_item:
            if existing_item["size"] > 0:
                print(f"  Item '{item_name}' already exists in library ({existing_item['size']} bytes), skipping upload")
                return existing_item["id"]
            else:
                print(f"  Item '{item_name}' exists but has 0 bytes (incomplete upload), deleting and re-uploading...")
                self.delete_library_item(existing_item["id"])

        # Try upload up to 2 times: first attempt, then retry after trusting cert if needed
        cert_trusted = False
        last_error: Optional[Exception] = None

        for attempt in range(2):
            item_id = None
            session_id = None
            try:
                # Create library item
                item_id = self._create_library_item(library_id, item_name)

                # Create update session
                session_id = self._create_update_session(item_id)

                # Upload files to the session
                self._upload_ovf_files(session_id, source)

                # Wait for PULL transfers to complete
                self._wait_for_session_files_ready(session_id)

                # Complete the session
                self._complete_update_session(session_id)

                print("  Upload completed successfully")
                return item_id

            except UntrustedSourceError as e:
                last_error = e
                self._cleanup_failed_upload(session_id, item_id)

                # Only try to trust cert on first attempt
                if attempt == 0 and not cert_trusted:
                    print("  Source TLS certificate not trusted — attempting to add to vCenter trust store...")
                    if self._trust_source_cert(source):
                        cert_trusted = True
                        print("  Retrying upload with trusted certificate...")
                        continue
                # Either already tried trusting, or trust failed — give up
                raise

            except Exception as e:
                last_error = e
                self._cleanup_failed_upload(session_id, item_id)
                raise

        # Should not reach here, but just in case
        if last_error:
            raise last_error
        raise RuntimeError("Upload failed unexpectedly")

    def _create_library_item(self, library_id: str, item_name: str) -> str:
        """Create a new library item. Returns the item ID."""
        create_spec = {
            "name": item_name,
            "library_id": library_id,
            "type": "ovf"
        }
        create_url = f"https://{self.host}/api/content/library/item"

        for attempt in range(3):
            response = self.rest_session.post(create_url, json=create_spec)
            if response.status_code != 503:
                break
            error_msg = self._extract_error_message(response)
            wait = 10 * (attempt + 1)
            print(f"  Content library service unavailable (503): {error_msg[:100]}... retrying in {wait}s")
            time.sleep(wait)

        if not response.ok:
            error_msg = self._extract_error_message(response)
            raise RuntimeError(f"Failed to create library item: {response.status_code} — {error_msg}")

        item_id = response.json()
        print(f"  Created library item with ID: {item_id}")
        return item_id

    def _create_update_session(self, item_id: str) -> str:
        """Create an update session for a library item. Returns the session ID."""
        session_spec = {"library_item_id": item_id}
        session_url = f"https://{self.host}/api/content/library/item/update-session"
        response = self.rest_session.post(session_url, json=session_spec)

        if not response.ok:
            raise RuntimeError(
                f"Failed to create update session: "
                f"{response.status_code} {response.reason}\n{response.text}"
            )

        session_id = response.json()
        print(f"  Created update session: {session_id}")
        return session_id

    def _complete_update_session(self, session_id: str) -> None:
        """
        Complete an update session and wait for the import task to finish.

        The complete API returns 200 OK immediately but the actual vCenter import
        task runs asynchronously. We must poll the session state until it reaches
        DONE (success) or ERROR (failure).
        """
        complete_url = f"https://{self.host}/api/content/library/item/update-session/{session_id}?action=complete"
        response = self.rest_session.post(complete_url)

        if not response.ok:
            # complete request itself was rejected
            body = response.text
            reason = self._extract_error_message(response) or body
            body_lower = body.lower()
            if "certificate" in body_lower and any(kw in body_lower for kw in
                    ("expired", "not trusted", "certificate_unknown", "self-signed")):
                raise UntrustedSourceError(f"Source TLS certificate not trusted: {body}")
            raise RuntimeError(f"Failed to complete update session: {reason}")

        # Poll until session reaches a terminal state (DONE or ERROR)
        session_url = f"https://{self.host}/api/content/library/item/update-session/{session_id}"
        deadline = time.time() + 300  # 5 min max for import task
        poll_interval = 5
        while time.time() < deadline:
            resp = self.rest_session.get(session_url)
            if resp.status_code == 404:
                # Session was removed by vCenter — treat as success (DONE auto-cleanup)
                return
            if not resp.ok:
                time.sleep(poll_interval)
                continue
            session_info = resp.json()
            state = session_info.get("state", "")
            if state == "DONE":
                return
            if state == "ERROR":
                error_msg = session_info.get("error_message", {})
                if isinstance(error_msg, dict):
                    msg = error_msg.get("default_message") or str(error_msg)
                else:
                    msg = str(error_msg) if error_msg else "unknown error"
                msg_lower = msg.lower()
                if "certificate" in msg_lower and any(kw in msg_lower for kw in
                        ("expired", "not trusted", "certificate_unknown", "self-signed")):
                    raise UntrustedSourceError(f"Source TLS certificate not trusted: {msg}")
                raise RuntimeError(f"Content library import failed: {msg}")
            # Still ACTIVE — keep waiting
            time.sleep(poll_interval)

        raise RuntimeError(f"Timed out waiting for import session {session_id} to complete")

    def _cleanup_failed_upload(self, session_id: Optional[str], item_id: Optional[str]) -> None:
        """Cancel session and delete incomplete library item after a failed upload."""
        if session_id:
            try:
                cancel_url = f"https://{self.host}/api/content/library/item/update-session/{session_id}?action=cancel"
                self.rest_session.post(cancel_url, timeout=30)
            except Exception:
                pass
        if item_id:
            try:
                self.delete_library_item(item_id)
            except Exception:
                pass

    def _wait_for_session_files_ready(self, session_id: str,
                                      timeout: int = 600, poll_interval: int = 10) -> int:
        """
        Poll the update session file list until every file is READY.
        Returns the total bytes of all transferred files.
        Raises RuntimeError if any file ends up in ERROR state or the timeout expires.
        This is required for PULL transfers where vCenter downloads files asynchronously.
        """
        files_url = f"https://{self.host}/api/content/library/item/update-session/{session_id}/file"
        session_url = f"https://{self.host}/api/content/library/item/update-session/{session_id}"
        deadline = time.time() + timeout
        while time.time() < deadline:
            # Check session state first — if it's no longer ACTIVE, fail fast
            session_resp = self.rest_session.get(session_url)
            if session_resp.status_code == 404:
                return 0
            if session_resp.ok:
                session_info = session_resp.json()
                session_state = session_info.get("state", "")
                if session_state not in ("ACTIVE", ""):
                    # Session is in ERROR, CANCELED, or DONE state
                    error_msg = session_info.get("error_message", {})
                    if isinstance(error_msg, dict):
                        error_msg = error_msg.get("default_message") or str(error_msg)
                    raise RuntimeError(
                        f"Session {session_id} is in {session_state} state: {error_msg or 'no details'}"
                    )

            response = self.rest_session.get(files_url)
            if response.status_code == 404:
                # Session was auto-cancelled by vCenter (e.g. PULL registration
                # failed). Proceed to complete so vCenter reports the real error.
                return 0
            response.raise_for_status()
            files = response.json()

            statuses = {f["name"]: f.get("status", "UNKNOWN") for f in files}
            not_ready = {name: st for name, st in statuses.items() if st != "READY"}

            if not not_ready:
                total_bytes = sum(f.get("size", 0) for f in files)
                print(f"  All {len(files)} file(s) ready ({total_bytes} bytes)")
                if total_bytes == 0 and files:
                    # vCenter marked files READY but transferred 0 bytes — broken upload
                    names = [f["name"] for f in files]
                    raise RuntimeError(
                        f"File transfer reported READY but 0 bytes transferred for: {names}. "
                        f"Source file likely missing or inaccessible."
                    )
                return total_bytes

            # If ANY file is in ERROR, fail fast — no point waiting for others.
            errors = {name: st for name, st in not_ready.items() if st == "ERROR"}
            if errors:
                # Fetch per-file error details if available
                details = {}
                for f in files:
                    if f.get("status") == "ERROR":
                        err = f.get("error_message")
                        if isinstance(err, dict):
                            err = err.get("default_message") or str(err)
                        details[f["name"]] = err or f.get("status")
                details_str = str(details)
                if "certificate" in details_str.lower() and (
                    "expired" in details_str.lower() or "not trusted" in details_str.lower()
                    or "certificate_unknown" in details_str.lower() or "self-signed" in details_str.lower()
                ):
                    raise UntrustedSourceError(
                        f"Source server TLS certificate not trusted by vCenter: {details_str}"
                    )
                raise RuntimeError(
                    f"File transfer failed for: {list(errors.keys())}. "
                    f"Details: {details}"
                )

            # Show file names with their current status
            status_info = [f"{name}={st}" for name, st in not_ready.items()]
            print(f"  Waiting for transfer: {status_info} ...")
            time.sleep(poll_interval)

        raise RuntimeError(
            f"Timed out after {timeout}s waiting for session {session_id} files to become READY"
        )

    @staticmethod
    def _extract_ovf_file_refs(ovf_content: str) -> list[str]:
        """
        Return all unique file references from an OVF descriptor.
        Captures any ovf:href value (vmdk, nvram, iso, etc.), excluding
        the OVF file itself and http(s) URLs (those are external references).
        """
        # Strip XML comments before extracting refs so commented-out File
        # elements with bogus paths (e.g. path traversals) are not registered.
        stripped = re.sub(r'<!--.*?-->', '', ovf_content, flags=re.DOTALL)
        refs = re.findall(r'ovf:href="([^"]+)"', stripped)
        seen = set()
        result = []
        for ref in refs:
            if ref in seen:
                continue
            seen.add(ref)
            # Skip external URLs and the .ovf descriptor itself
            if ref.startswith('http://') or ref.startswith('https://'):
                continue
            if ref.endswith('.ovf') or ref.endswith('.mf') or ref.endswith('.cert'):
                continue
            result.append(ref)
        return result

    def _upload_ovf_files(self, session_id: str, source: str) -> None:
        """
        Upload OVF files to the update session.

        For remote URLs: uses PULL so vCenter downloads directly.
        For local files: reads and pushes content to vCenter.
        """
        is_local = os.path.exists(source)
        filename = os.path.basename(source)

        if is_local:
            if filename.endswith('.ova'):
                print(f"  Uploading local OVA {filename} ({os.path.getsize(source)} bytes)...")
                self._upload_file_from_path(session_id, filename, source)
            elif filename.endswith('.ovf'):
                base_dir = os.path.dirname(source)
                with open(source) as f:
                    ovf_content = f.read()
                self._upload_file_content(session_id, filename, ovf_content.encode())
                for ref in self._extract_ovf_file_refs(ovf_content):
                    ref_path = os.path.join(base_dir, ref)
                    if os.path.exists(ref_path):
                        print(f"  Uploading {ref} ({os.path.getsize(ref_path)} bytes)...")
                        self._upload_file_from_path(session_id, ref, ref_path)
                    else:
                        print(f"  Warning: referenced file not found locally, skipping: {ref}")
            else:
                raise ValueError(f"Unsupported file type: {filename}")
        else:
            # Remote URL - use PULL; pass the full cert chain so vCenter can verify the server
            ssl_chain = self._get_ssl_chain(source)
            if filename.endswith('.ova'):
                self._upload_file_from_url(session_id, source, filename, ssl_chain)
            elif filename.endswith('.ovf'):
                base_url = source.rsplit('/', 1)[0] + '/'
                print(f"  Downloading OVF descriptor from {source}...")
                response = requests.get(source, verify=False, timeout=60)
                response.raise_for_status()
                ovf_content = response.text
                self._upload_file_content(session_id, filename, ovf_content.encode())
                for ref in self._extract_ovf_file_refs(ovf_content):
                    ref_url = urljoin(base_url, ref)
                    print(f"  Adding file for transfer: {ref}")
                    self._upload_file_from_url(session_id, ref_url, ref, ssl_chain)
            else:
                raise ValueError(f"Unsupported file type: {filename}")


    def _trust_source_cert(self, url: str) -> bool:
        """
        Add the source server's TLS certificate chain to vCenter's content library
        trust store so that subsequent PULL transfers from that server are accepted.

        Returns True if the cert was successfully added, False otherwise.
        """
        chain_pem = self._get_ssl_chain(url)
        if not chain_pem:
            print("  Could not fetch source certificate — cannot force-trust")
            return False

        trust_url = f"https://{self.host}/api/content/trusted-certificates"
        response = self.rest_session.post(trust_url, json={"cert_text": chain_pem})
        if response.ok:
            print("  Added source certificate to vCenter content library trust store")
            return True
        # 400 with "already exists" is fine — cert is already trusted
        body = response.text
        if response.status_code == 400 and "already" in body.lower():
            print("  Source certificate already trusted by vCenter")
            return True
        print(f"  Warning: could not add certificate to trust store: {response.status_code} {body}")
        return False

    def _get_ssl_chain(self, url: str) -> Optional[str]:
        """
        Fetch the full TLS certificate chain (leaf + intermediates) from the server
        in PEM format, concatenated.  vCenter needs the full chain to verify the server
        when performing PULL transfers.

        Uses `openssl s_client` to retrieve the chain; falls back to the leaf-only cert
        via the ssl module if openssl is not available.
        """
        import subprocess as _sp
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        print(f"  Fetching TLS certificate chain from {hostname}:{port}...")
        try:
            result = _sp.run(
                ["openssl", "s_client", "-connect", f"{hostname}:{port}",
                 "-showcerts", "-servername", hostname],
                input=b"",
                capture_output=True,
                timeout=15,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            # Extract all PEM blocks from the output
            pem_blocks = re.findall(
                r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
                output, re.DOTALL
            )
            if pem_blocks:
                chain = "\n".join(pem_blocks)
                print(f"  Got {len(pem_blocks)} certificate(s) in chain for {hostname}")
                return chain
        except Exception as e:
            print(f"  Warning: openssl s_client failed ({e}), falling back to leaf cert")

        # Fallback: leaf cert only via ssl module
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            import socket as _sock
            with _sock.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
            cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
            print(f"  Got leaf certificate for {hostname}")
            return cert_pem
        except Exception as e:
            print(f"  Warning: Could not fetch SSL certificate: {e}")
            return None

    @staticmethod
    def _encode_url(url: str) -> str:
        """Percent-encode spaces and other invalid URI characters in a URL's path."""
        from urllib.parse import urlparse, quote, urlunparse
        p = urlparse(url)
        # quote the path, preserving '/' separators and already-encoded sequences
        encoded_path = quote(p.path, safe='/:@!$&\'()*+,;=')
        return urlunparse(p._replace(path=encoded_path))

    def _upload_file_from_url(self, session_id: str, file_url: str, filename: str,
                               ssl_cert: Optional[str] = None) -> None:
        """
        Register a file for PULL transfer in the update session.
        vCenter will fetch the file directly from the URL and report any errors.
        """
        file_url = self._encode_url(file_url)
        add_spec = {
            "name": filename,
            "source_type": "PULL",
            "source_endpoint": {
                "uri": file_url
            }
        }
        if ssl_cert:
            add_spec["source_endpoint"]["ssl_certificate"] = ssl_cert

        add_url = f"https://{self.host}/api/content/library/item/update-session/{session_id}/file"
        response = self.rest_session.post(add_url, json=add_spec)
        if not response.ok:
            # Extract error message from response
            error_msg = response.text
            try:
                err_json = response.json()
                msgs = [m.get("default_message", "") for m in err_json.get("messages", []) if m.get("default_message")]
                if msgs:
                    error_msg = " ".join(msgs)
            except Exception:
                pass
            raise RuntimeError(
                f"Failed to add file {filename} for PULL: "
                f"{response.status_code} {response.reason} — {error_msg}"
            )
        print(f"  Added file {filename} (PULL from {file_url})")

    def _upload_file_content(self, session_id: str, filename: str, content: bytes) -> None:
        """Upload small file content (e.g. OVF descriptor) directly to the update session."""
        self._upload_file_path_or_bytes(session_id, filename, size=len(content), data=content)

    def _upload_file_from_path(self, session_id: str, filename: str, file_path: str) -> None:
        """Stream a local file to the update session without loading it into memory."""
        size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            self._upload_file_path_or_bytes(session_id, filename, size=size, data=f)

    def _upload_file_path_or_bytes(self, session_id: str, filename: str,
                                   size: int, data) -> None:
        """
        Core PUSH upload: register the file with the session then stream data to
        the upload endpoint. data may be bytes or an open file object.
        """
        add_spec = {
            "name": filename,
            "source_type": "PUSH",
            "size": size,
        }
        add_url = f"https://{self.host}/api/content/library/item/update-session/{session_id}/file"
        response = self.rest_session.post(add_url, json=add_spec)
        if not response.ok:
            raise RuntimeError(
                f"Failed to add file {filename} for PUSH: "
                f"{response.status_code} {response.reason}\n{response.text}"
            )
        file_info = response.json()

        upload_uri = file_info.get("upload_endpoint", {}).get("uri")
        if upload_uri:
            upload_response = self.rest_session.put(
                upload_uri,
                data=data,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(size),
                }
            )
            if not upload_response.ok:
                raise RuntimeError(
                    f"Failed to upload content for {filename}: "
                    f"{upload_response.status_code} {upload_response.reason}\n{upload_response.text}"
                )
        print(f"  Uploaded file {filename} ({size} bytes)")


class SupervisorClient:
    """Client for Supervisor operations via SSH."""

    def __init__(self, host: str, password: str, user: str = "root"):
        self.host = host
        self.user = user
        self.password = password
        self.ssh = None

    def connect(self) -> None:
        """Connect to Supervisor via SSH."""
        print(f"Connecting to Supervisor {self.host} via SSH...")
        self._open_ssh()
        print("  Connected to Supervisor")

    def _open_ssh(self) -> None:
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(
            hostname=self.host,
            username=self.user,
            password=self.password,
            look_for_keys=False,
            allow_agent=False
        )

    def disconnect(self) -> None:
        """Disconnect from Supervisor."""
        if self.ssh:
            self.ssh.close()
            print("Disconnected from Supervisor")

    def run_kubectl(self, args: str, check: bool = True) -> tuple[str, str, int]:
        """Run a kubectl command and return stdout, stderr, and return code."""
        cmd = f"kubectl {args}"
        for attempt in range(2):
            try:
                stdin, stdout, stderr = self.ssh.exec_command(cmd)
                exit_code = stdout.channel.recv_exit_status()
                stdout_str = stdout.read().decode()
                stderr_str = stderr.read().decode()
                break
            except (paramiko.SSHException, EOFError, OSError) as e:
                if attempt == 0:
                    print(f"  SSH connection lost ({e}), reconnecting...")
                    self._open_ssh()
                else:
                    raise RuntimeError(f"SSH connection failed after reconnect: {e}") from e

        if check and exit_code != 0:
            raise RuntimeError(f"kubectl command failed: {cmd}\n{stderr_str}")

        return stdout_str, stderr_str, exit_code

    def namespace_exists(self, namespace: str) -> bool:
        """Check if a namespace exists."""
        _, _, exit_code = self.run_kubectl(f"get namespace {namespace}", check=False)
        return exit_code == 0

    def get_content_library(self, namespace: str, name: str) -> Optional[dict]:
        """Get content library info."""
        stdout, _, exit_code = self.run_kubectl(
            f"get contentlibrary -n {namespace} {name} -o json",
            check=False
        )
        if exit_code != 0:
            return None
        return json.loads(stdout)

    def list_content_libraries(self, namespace: str) -> list[str]:
        """List content libraries in a namespace."""
        stdout, _, _ = self.run_kubectl(
            f"get contentlibrary -n {namespace} -o jsonpath='{{.items[*].metadata.name}}'"
        )
        return stdout.strip("'").split() if stdout.strip("'") else []

    def wait_for_vmi(self, namespace: str, image_name: str,
                     timeout: int = VMI_WAIT_TIMEOUT) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Wait for a VirtualMachineImage to become Ready.

        Returns (vmi_name, None, None) on success.
        Returns (None, reason, last_seen_vmi_name) on terminal failure or timeout,
        where last_seen_vmi_name is the VMI CR name observed during polling (useful
        for fetching relevant vmop logs even on failure).
        """
        print(f"Waiting for VirtualMachineImage containing '{image_name}'...")
        start_time = time.time()
        last_vmi_msg = ""
        last_seen_vmi_name = ""

        while time.time() - start_time < timeout:
            stdout, _, _ = self.run_kubectl(
                f"get vmi -n {namespace} -o json",
                check=False
            )
            if stdout:
                try:
                    vmi_list = json.loads(stdout)
                    for item in vmi_list.get("items", []):
                        vmi_name = item.get("metadata", {}).get("name", "")
                        display_name = item.get("status", {}).get("name", "")
                        if image_name.lower() == display_name.lower():
                            last_seen_vmi_name = vmi_name
                            conditions = item.get("status", {}).get("conditions", [])
                            for cond in conditions:
                                if cond.get("type") == "Ready":
                                    if cond.get("status") == "True":
                                        print(f"  Found ready VMI: {vmi_name}")
                                        return vmi_name, None, None
                                    msg = cond.get("message", "")
                                    if msg:
                                        last_vmi_msg = msg
                                    # Only bail out on messages that indicate a permanent
                                    # vmop failure. Transient states ("cache not ready",
                                    # "VirtualMachineImageNotSynced" with no detail) are
                                    # normal during initial sync — keep polling.
                                    _TERMINAL_VMI_ERRORS = (
                                        "failed to get hardware",
                                        "failed to marshal",
                                        "failed to create or patch",
                                        "control characters are not allowed",
                                        "yaml:",
                                    )
                                    if msg and any(e in msg for e in _TERMINAL_VMI_ERRORS):
                                        reason = f"VirtualMachineImage not ready: {msg}"
                                        print(f"  VMI terminal error: {reason}")
                                        return None, reason, last_seen_vmi_name
                except json.JSONDecodeError:
                    pass

            print(f"  Waiting... ({int(time.time() - start_time)}s)")
            time.sleep(POLL_INTERVAL)

        timeout_reason = f"VirtualMachineImage for '{image_name}' did not become ready within {timeout}s"
        if last_vmi_msg:
            timeout_reason += f": {last_vmi_msg}"
        return None, timeout_reason, last_seen_vmi_name or None

    def create_vm(self, namespace: str, vm_name: str, image_name: str,
                  vm_class: str, storage_class: str,
                  ovf_info: Optional[OvfInfo] = None,
                  vapp_config: Optional[list] = None,
                  network_type: str = "nsx") -> None:
        """
        Create a VirtualMachine CR.

        Args:
            namespace: Kubernetes namespace
            vm_name: Name for the VM
            image_name: VirtualMachineImage name
            vm_class: VirtualMachineClass name
            storage_class: StorageClass name for the VM's disks
            ovf_info: Parsed OVF info for network interface population
            vapp_config: List of vAppConfig property dicts to inject directly into
                         spec.bootstrap.vAppConfig.properties. When provided, these
                         are used as-is instead of OVF-derived defaults.
        """
        spec: dict = {
            "className": vm_class,
            "imageName": image_name,
            "storageClass": storage_class,
            "powerState": "PoweredOn"
        }

        if not (ovf_info and ovf_info.guest_id):
            if ovf_info and ovf_info.has_buslogic:
                print("  OVF has BusLogic SCSI controller — skipping guestID override")
            else:
                spec["guestID"] = "otherLinux64Guest"

        # Add network interfaces from OVF network definitions
        if ovf_info and ovf_info.has_networks():
            interfaces = []
            for i, net in enumerate(ovf_info.networks):
                if network_type == "vds":
                    net_ref = {
                        "apiVersion": "netoperator.vmware.com/v1alpha1",
                        "kind": "Network",
                        "name": ""
                    }
                else:  # nsx (default)
                    net_ref = {
                        "apiVersion": "crd.nsx.vmware.com/v1alpha1",
                        "kind": "SubnetSet",
                        "name": ""
                    }
                interfaces.append({"name": f"eth{i}", "network": net_ref})
            if interfaces:
                spec["network"] = {"interfaces": interfaces}

        # vAppConfig: use provided config directly, or fall back to OVF defaults
        if vapp_config:
            spec["bootstrap"] = {
                "vAppConfig": {"properties": vapp_config}
            }
        elif ovf_info and ovf_info.has_properties():
            props = auto_fill_vapp_properties(ovf_info)
            spec["bootstrap"] = {
                "vAppConfig": {"properties": props}
            }

        vm_manifest = {
            "apiVersion": "vmoperator.vmware.com/" + DEFAULT_VM_VERSION,
            "kind": "VirtualMachine",
            "metadata": {
                "name": vm_name,
                "namespace": namespace
            },
            "spec": spec
        }

        yaml_content = yaml.dump(vm_manifest, default_flow_style=False)
        print(f"Creating VirtualMachine {vm_name}...")
        print(f"  Spec:\n{yaml_content}")

        # Apply via kubectl with reconnect on SSH failure
        cmd = f"cat <<'VMEOF' | kubectl apply -f -\n{yaml_content}\nVMEOF"
        for attempt in range(2):
            try:
                stdin, stdout, stderr = self.ssh.exec_command(cmd)
                exit_code = stdout.channel.recv_exit_status()
                stderr_str = stderr.read().decode()
                break
            except (paramiko.SSHException, EOFError, OSError) as e:
                if attempt == 0:
                    print(f"  SSH connection lost ({e}), reconnecting...")
                    self._open_ssh()
                else:
                    raise RuntimeError(f"SSH connection failed after reconnect: {e}") from e
        if exit_code != 0:
            raise RuntimeError(f"Failed to create VM: {stderr_str}")

        print(f"  VirtualMachine {vm_name} created")

    def wait_for_vm_powered_on(self, namespace: str, vm_name: str,
                               vcenter: Optional[Any] = None,
                               timeout: int = VM_TOOLS_WAIT_TIMEOUT) -> tuple[bool, dict]:
        """
        Wait for the VM to be powered on.

        Power state is checked via the vSphere API (vcenter.is_vm_powered_on) when
        vcenter is provided, falling back to status.powerState in the CR otherwise.
        The CR is still polled each iteration to detect terminal error conditions early.

        Returns (powered_on, vm_status_dict).
        """
        print(f"Waiting for {vm_name} to power on...")
        start_time = time.time()
        last_status: dict = {}

        while time.time() - start_time < timeout:
            stdout, _, _ = self.run_kubectl(
                f"get vm -n {namespace} {vm_name} -o json",
                check=False
            )
            if stdout:
                try:
                    vm_cr = json.loads(stdout)
                    last_status = vm_cr.get("status", {})
                    phase = last_status.get("phase", "Unknown")
                    conditions = last_status.get("conditions", [])

                    # Bail out immediately on any terminal error condition
                    error_conditions = [
                        c for c in conditions
                        if c.get("reason") == "Error" and c.get("status") == "False"
                    ]
                    if error_conditions:
                        msgs = "; ".join(
                            f"{c.get('type')}: {c.get('message', '')}"
                            for c in error_conditions
                        )
                        print(f"  Terminal error condition(s) detected: {msgs}")
                        return False, last_status

                    # Check power state via vSphere API if available, else fall back to CR
                    if vcenter is not None:
                        powered_on = vcenter.is_vm_powered_on(vm_name)
                    else:
                        powered_on = last_status.get("powerState", "") == "PoweredOn"

                    if powered_on:
                        print(f"  VM is powered on")
                        return True, last_status

                    print(f"  Waiting... ({int(time.time() - start_time)}s) - Phase: {phase}")
                except json.JSONDecodeError:
                    pass
            time.sleep(POLL_INTERVAL)

        return False, last_status

    def get_vm_status_reason(self, namespace: str, vm_name: str) -> str:
        """
        Extract a human-readable reason from the VM CR status conditions.

        Looks at .status.conditions for any False or error conditions and
        returns their message, falling back to phase if nothing useful found.
        """
        stdout, _, _ = self.run_kubectl(
            f"get vm -n {namespace} {vm_name} -o json",
            check=False
        )
        if not stdout:
            return "VM not found"
        try:
            vm = json.loads(stdout)
            status = vm.get("status", {})
            phase = status.get("phase", "Unknown")
            conditions = status.get("conditions", [])
            reasons = []
            for cond in conditions:
                if cond.get("status") != "True":
                    msg = cond.get("message", "")
                    reason = cond.get("reason", "")
                    ctype = cond.get("type", "")
                    part = f"{ctype}: {reason}"
                    if msg:
                        part += f" - {msg}"
                    reasons.append(part)
            if reasons:
                return f"Phase={phase}; " + "; ".join(reasons)
            return f"Phase={phase}"
        except json.JSONDecodeError:
            return "Could not parse VM status"

    def get_vmop_logs(self, *search_terms: str, since_seconds: Optional[int] = None) -> str:
        """
        Fetch vmop controller-manager logs with lines matching ANY of the search terms.

        When since_seconds is provided, fetches logs from that many seconds ago
        (more reliable than --tail for long runs). Falls back to --tail=500.

        Returns relevant log lines as a single string, empty if none found.
        """
        if not search_terms:
            return ""
        if since_seconds is not None:
            log_arg = f"--since={since_seconds}s"
        else:
            log_arg = "--tail=500"
        # Escape regex special chars in each term, join with | for alternation
        escaped = "|".join(
            t.replace("\\", "\\\\").replace(".", r"\.").replace("[", r"\[").replace("]", r"\]")
            for t in search_terms
        )
        stdout, _, _ = self.run_kubectl(
            f"logs deploy/vmware-system-vmop-controller-manager "
            f"-n vmware-system-vmop {log_arg} 2>/dev/null | grep -E '{escaped}' || true",
            check=False
        )
        return stdout.strip() if stdout else ""

    def get_vmop_logs_for_vm(self, vm_name: str, since_seconds: Optional[int] = None) -> str:
        """Fetch vmop logs relevant to a VirtualMachine by name."""
        return self.get_vmop_logs(vm_name, since_seconds=since_seconds)

    def delete_vm(self, namespace: str, vm_name: str) -> None:
        """Delete a VirtualMachine."""
        self.run_kubectl(f"delete vm -n {namespace} {vm_name} --ignore-not-found")
        print(f"  Deleted VM {vm_name}")

    def delete_all_vms(self, namespace: str) -> None:
        """Delete all VirtualMachines in the given namespace."""
        stdout, _, _ = self.run_kubectl(
            f"get vm -n {namespace} -o jsonpath='{{.items[*].metadata.name}}'", check=False
        )
        names = stdout.strip().split() if stdout.strip() else []
        if not names:
            print(f"  No VMs found in namespace '{namespace}'")
            return
        print(f"  Deleting {len(names)} VM(s) in namespace '{namespace}'...")
        for name in names:
            try:
                self.run_kubectl(f"delete vm -n {namespace} {name} --ignore-not-found")
                print(f"    Deleted VM '{name}'")
            except Exception as e:
                print(f"    Warning: could not delete VM '{name}': {e}")


def discover_ovfs(base_url: str) -> list[str]:
    """
    Discover OVF/OVA files from an Artifactory repository URL.

    Uses the Artifactory UI native browser API which returns all entries
    including remote/uncached ones that the storage API misses. Directory
    traversal is parallelised with a thread pool for speed.

    Args:
        base_url: Artifactory UI or download base URL (e.g. ending in testdata/)

    Returns:
        Sorted list of OVF/OVA download URLs
    """
    print(f"Discovering OVFs from {base_url}...")

    # Derive host and repo/path to build the UI native browser API URL.
    # Accepted input forms:
    #   https://host/ui/native/repo/path/
    #   https://host/artifactory/repo/path/
    parsed = urlparse(base_url)
    host = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")

    if "/ui/native/" in path:
        repo_path = path.split("/ui/native/", 1)[1]
    elif "/artifactory/" in path:
        repo_path = path.split("/artifactory/", 1)[1]
    else:
        repo_path = path.lstrip("/")

    ui_base = f"{host}/ui/api/v1/ui/nativeBrowser/{repo_path}"
    dl_base = f"{host}/artifactory/{repo_path}"

    ovfs: list[str] = []
    lock = threading.Lock()

    def browse(ui_path: str, dl_path: str,
               executor: "concurrent.futures.ThreadPoolExecutor",
               futures: list) -> None:
        try:
            r = requests.get(ui_path, headers={"Accept": "application/json"},
                             verify=False, timeout=30)
            r.raise_for_status()
            data = r.json()
            for child in data.get("children", []):
                name = child.get("name", "")
                if child.get("folder"):
                    child_ui = ui_path.rstrip("/") + "/" + name
                    child_dl = dl_path.rstrip("/") + "/" + name
                    f = executor.submit(browse, child_ui, child_dl, executor, futures)
                    with lock:
                        futures.append(f)
                elif name.lower().endswith((".ovf", ".ova")) and not name.startswith("._"):
                    with lock:
                        ovfs.append(dl_path.rstrip("/") + "/" + name)
        except Exception as e:
            print(f"  Warning: Could not browse {ui_path}: {e}")

    futures: list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures.append(executor.submit(browse, ui_base, dl_base, executor, futures))
        i = 0
        while i < len(futures):
            futures[i].result()
            i += 1

    ovfs.sort()
    print(f"  Found {len(ovfs)} OVF/OVA files")
    return ovfs


@dataclass
class OvfEntry:
    """A single OVF/OVA to deploy."""
    name: str
    source: str
    config_file: Optional[str] = None  # Path to YAML file with vAppConfig properties


@dataclass
class DeployResult:
    """Result of deploying a single OVF/OVA."""
    name: str
    source: str
    vm_name: str
    status: str          # SUCCESS / PARTIAL / FAILED
    reason: str          # Human-readable explanation
    vmop_logs: str = ""  # Relevant vmop log lines


def load_ovf_list(path: str) -> list[OvfEntry]:
    """
    Load OVF entries from a CSV file.

    Format: name,source[,config_file]
      name        - item/VM name
      source      - local file path or remote URL to OVF/OVA
      config_file - optional path to YAML file with vAppConfig properties

    Lines starting with '#' are treated as comments.
    """
    entries = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split(',', 2)]
            if len(parts) < 2:
                print(f"  Warning: Skipping malformed line {lineno} in {path}: {line!r}")
                continue
            name, source = parts[0], parts[1]
            config_file = parts[2] if len(parts) == 3 and parts[2] else None
            if name and source:
                entries.append(OvfEntry(name=name, source=source, config_file=config_file))
    print(f"Loaded {len(entries)} OVF entries from {path}")
    return entries


def _smart_value_for_property(prop: OvfProperty, for_vcenter: bool = False) -> str:
    """
    Return a smart value for an OVF property.

    When for_vcenter=False (VM Service deploy): returns Go template expressions
    that VM Operator evaluates at boot time from the VM's network context.

    When for_vcenter=True (validate / direct vCenter deploy): returns plain
    placeholder values that vCenter's OVF deploy API accepts as-is.
    """
    import random
    import string

    key = prop.key.lower()
    label = prop.label.lower()
    desc = prop.description.lower()
    combined = f"{key} {label} {desc}"
    typ = prop.type.lower()
    qualifiers = prop.qualifiers.lower() if prop.qualifiers else ""

    # --- vmw:qualifiers-based rules (most authoritative signal) ---
    # e.g. Ip('Network 1'), Netmask('Network 1'), Gateway('Network 1'), Dns('Network 1')
    if qualifiers.startswith("ip("):
        return "192.0.2.1" if for_vcenter else \
            '{{ V1alpha5_FormatIP (index (index .V1alpha5.Net.Devices 0).IPAddresses 0) "" }}'
    if qualifiers.startswith("netmask("):
        return "255.255.255.0" if for_vcenter else \
            '{{ V1alpha5_SubnetMask (index (index .V1alpha5.Net.Devices 0).IPAddresses 0) }}'
    if qualifiers.startswith("gateway("):
        return "192.0.2.254" if for_vcenter else \
            "{{ (index .V1alpha5.Net.Devices 0).Gateway4 }}"
    if qualifiers.startswith("dns("):
        return "8.8.8.8" if for_vcenter else \
            '{{ V1alpha5_FormatNameservers -1 "," }}'

    # --- OVF type-based rules ---
    if typ == "boolean":
        default = prop.default.capitalize() if prop.default else ""
        return default if default in ("True", "False") else "False"

    if typ in ("uint8", "sint8"):
        return prop.default if prop.default else "0"

    if typ in ("uint16", "sint16"):
        return prop.default if prop.default else "0"

    if typ in ("uint32", "sint32"):
        return prop.default if prop.default else "0"

    if typ in ("uint64", "sint64"):
        return prop.default if prop.default else "0"

    if typ in ("real32", "real64"):
        return prop.default if prop.default else "0.0"

    # Non-user-configurable with a default: keep it as-is.
    if not prop.user_configurable and prop.default:
        return prop.default

    if typ == "password":
        chars = string.ascii_letters + string.digits + "!@#$"
        return "VMware1!" + "".join(random.choices(chars, k=8))

    if typ == "ip":
        return "192.0.2.1" if for_vcenter else \
            '{{ V1alpha5_FormatIP (index (index .V1alpha5.Net.Devices 0).IPAddresses 0) "" }}'

    # --- Key/label/description pattern matching ---

    # IPv6-specific fields: leave empty — we don't configure IPv6 addresses
    if any(x in combined for x in ("ipv6", "ip6", "inet6")):
        return ""

    # Subnet prefix length (numeric, e.g. "24") — must not also match "netmask"
    if any(x in combined for x in ("prefixlen", "prefix_len", "prefix-len")) or \
       (any(x in combined for x in ("prefix", "cidr")) and
            not any(x in combined for x in ("netmask", "subnet mask", "subnetmask"))):
        return str(DEFAULT_SUBNET_PREFIX_LENGTH)

    # Subnet mask (dotted-decimal, e.g. "255.255.255.0")
    if any(x in combined for x in ("netmask", "subnet mask", "subnetmask", "net.mask", "net_mask")):
        return "255.255.255.0" if for_vcenter else \
            '{{ V1alpha5_SubnetMask (index (index .V1alpha5.Net.Devices 0).IPAddresses 0) }}'

    # IP address (but not gateway/dns) — also matches short keys like "ip0", "ip1"
    if (any(x in combined for x in ("ip address", "ip_address", "ipaddress", "net.addr",
                                    "net_addr", "nsx_ip", "mgmt_ip", "management ip",
                                    "pnid", "hostname")) or
            re.search(r'\bip\d*\b', key)) and \
       not any(x in combined for x in ("gateway", "dns", "nameserver", "netmask", "subnet")):
        return "192.0.2.1" if for_vcenter else \
            '{{ V1alpha5_FormatIP (index (index .V1alpha5.Net.Devices 0).IPAddresses 0) "" }}'

    # Gateway — also matches "gateway0", "gateway1"
    if any(x in combined for x in ("gateway", "default route", "net.gateway", "net_gateway")):
        return "192.0.2.254" if for_vcenter else \
            "{{ (index .V1alpha5.Net.Devices 0).Gateway4 }}"

    # DNS / nameservers — also matches "dns0", "DNS0"
    if any(x in combined for x in ("dns", "nameserver", "name server", "net.dns")):
        return "8.8.8.8" if for_vcenter else \
            '{{ V1alpha5_FormatNameservers -1 "," }}'

    # Domain / search path
    if any(x in combined for x in ("domain", "searchpath", "search path", "search_path", "dnsdomain")):
        return "lvn.broadcom.net"

    # Password fields by key/label
    if any(x in combined for x in ("password", "passwd", "secret", "credential")):
        chars = string.ascii_letters + string.digits + "!@#$"
        return "VMware1!" + "".join(random.choices(chars, k=8))

    # Use the OVF default if one exists
    if prop.default:
        return prop.default

    # Generic string fallback: random alphanumeric
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def auto_fill_vapp_properties(ovf_info: OvfInfo) -> list[dict]:
    """
    Build a vAppConfig properties list from OVF property definitions,
    filling each value with a smart template expression or random fallback.
    Only user-configurable properties (or those with no default) are filled;
    non-user-configurable properties with defaults keep their defaults.
    """
    result = []
    for prop in ovf_info.properties:
        value = _smart_value_for_property(prop)
        result.append({"key": prop.key, "value": {"value": value}})
        print(f"    auto-fill: {prop.key!r} = {value!r}")
    return result


def load_vapp_config(config_file: str) -> list[dict]:
    """
    Load vAppConfig properties from a YAML file.

    The file should contain a 'properties' list in the same format used
    in the VirtualMachine CR spec.bootstrap.vAppConfig.properties, e.g.:

      properties:
        - key: nsx_hostname
          value:
            value: nsx-manager-1
        - key: nsx_passwd_0
          value:
            value: VMware1!VMware1!
    """
    with open(config_file) as f:
        data = yaml.safe_load(f)
    props = data.get("properties", [])
    print(f"  Loaded {len(props)} vApp properties from {config_file}")
    return props


def ovf_list_from_discovered(urls: list[str]) -> list[OvfEntry]:
    """
    Convert a list of discovered OVF/OVA URLs into OvfEntry objects.

    When multiple URLs share the same filename stem (e.g. nostalgia.ovf in
    different directories), the name is disambiguated by prepending the
    immediate parent directory: nostalgia/nostalgia, nostalgia_small/nostalgia, etc.
    """
    # First pass: collect raw stem → list of urls
    from collections import defaultdict
    stem_to_urls: dict[str, list[str]] = defaultdict(list)
    for url in urls:
        filename = os.path.basename(urlparse(url).path)
        stem = os.path.splitext(filename)[0]
        stem_to_urls[stem].append(url)

    entries = []
    for url in urls:
        parsed = urlparse(url)
        path_parts = parsed.path.rstrip("/").split("/")
        filename = path_parts[-1]
        stem = os.path.splitext(filename)[0]

        if len(stem_to_urls[stem]) > 1:
            # Walk up path segments until we find one that makes the name unique,
            # or use up to 2 levels if all collide.
            for depth in range(1, min(3, len(path_parts))):
                parent = path_parts[-(depth + 1)]
                candidate = f"{parent}/{stem}"
                # Unique if no other URL in the same stem group produces the same candidate
                others = [u for u in stem_to_urls[stem] if u != url]
                if not any(
                    urlparse(u).path.rstrip("/").split("/")[-(depth + 1)] == parent
                    for u in others
                ):
                    name = candidate.replace("/", "_")
                    break
            else:
                # Full path fallback: use everything after base_path separator
                name = "_".join(path_parts[-3:-1]) + "_" + stem
        else:
            name = stem

        entries.append(OvfEntry(name=name, source=url))
    return entries


def fetch_ovf_info(source: str) -> Optional[OvfInfo]:
    """Parse OVF info from a local file path or remote URL."""
    if os.path.exists(source):
        return fetch_ovf_from_file(source)
    return fetch_ovf_from_url(source)


_STATUS_STYLE = {
    "SUCCESS":      ("✅", "#1a7f37", "#dafbe1"),
    "FAILED":       ("❌", "#cf222e", "#ffebe9"),
    "SETUP_FAILED": ("🔧", "#8250df", "#fbefff"),
    "SKIPPED":      ("⏭",  "#57606a", "#f6f8fa"),
}


def _html_escape(text: str) -> str:
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _timing_html(start_time: Optional[float], end_time: float) -> str:
    """Return an HTML snippet with start, end, and elapsed time, or empty string."""
    if start_time is None:
        return ""
    start_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
    end_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))
    elapsed = int(end_time - start_time)
    h, rem = divmod(elapsed, 3600)
    m, s = divmod(rem, 60)
    elapsed_str = f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")
    return (
        f" &nbsp;|&nbsp; Start: {start_str}"
        f" &nbsp;|&nbsp; End: {end_str}"
        f" &nbsp;|&nbsp; Elapsed: {elapsed_str}"
    )


def write_report(results: list[DeployResult], report_path: str,
                 start_time: Optional[float] = None,
                 title: str = "OVF Deploy Test Report",
                 vcenter_ip: str = "",
                 show_vm_column: bool = True) -> None:
    """Write an HTML deployment results report and print a summary to stdout."""
    # Ensure the output path ends in .html
    if not report_path.endswith(".html"):
        report_path = os.path.splitext(report_path)[0] + ".html"

    now = time.time()
    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    # --- Build table rows ---
    rows_html = []
    for r in results:
        icon, fg, bg = _STATUS_STYLE.get(r.status, ("•", "#24292f", "#f6f8fa"))
        name_cell = (
            f'<a href="{_html_escape(r.source)}" target="_blank">'
            f'{_html_escape(r.name)}</a>'
            if r.source.startswith("http")
            else _html_escape(r.name)
        )
        badge = (
            f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
            f'background:{bg};color:{fg};font-weight:600;font-size:0.85em;'
            f'border:1px solid {fg}33;">{icon} {_html_escape(r.status)}</span>'
        )
        reason_escaped = _html_escape(r.reason)
        logs_cell = ""
        if r.vmop_logs:
            logs_escaped = _html_escape(r.vmop_logs)
            logs_cell = (
                f'<details><summary style="cursor:pointer;color:#57606a;font-size:0.8em;">'
                f'vmop logs</summary>'
                f'<pre style="font-size:0.75em;background:#f6f8fa;padding:8px;'
                f'border-radius:4px;overflow:auto;max-height:300px;">'
                f'{logs_escaped}</pre></details>'
            )
        vm_cell = f'<td style="padding:8px 12px;font-family:monospace;font-size:0.9em;">{_html_escape(r.vm_name)}</td>' if show_vm_column else ""
        rows_html.append(
            f"<tr>"
            f'<td style="padding:8px 12px;">{name_cell}</td>'
            f'{vm_cell}'
            f'<td style="padding:8px 12px;text-align:center;">{badge}</td>'
            f'<td style="padding:8px 12px;font-size:0.85em;color:#24292f;">'
            f'{reason_escaped}{("<br>" + logs_cell) if logs_cell else ""}</td>'
            f"</tr>"
        )

    # --- Summary counts ---
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    summary_parts = []
    for status, (icon, fg, bg) in _STATUS_STYLE.items():
        n = counts.get(status, 0)
        if n:
            summary_parts.append(
                f'<span style="margin-right:16px;color:{fg};font-weight:600;">'
                f'{icon} {status}: {n}</span>'
            )

    # Build title with vCenter IP if provided
    full_title = f"{title} — {vcenter_ip}" if vcenter_ip else title
    vm_header = "<th>VM Name</th>" if show_vm_column else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{full_title} — {generated}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         margin: 32px; color: #24292f; background: #fff; }}
  h1   {{ font-size: 1.4em; margin-bottom: 4px; }}
  .meta {{ color: #57606a; font-size: 0.85em; margin-bottom: 20px; }}
  .summary {{ margin-bottom: 20px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.9em; }}
  thead th {{ background: #f6f8fa; border-bottom: 2px solid #d0d7de;
              padding: 8px 12px; text-align: left; font-weight: 600; }}
  tbody tr:nth-child(even) {{ background: #f6f8fa; }}
  tbody tr:hover {{ background: #eaf5ff; }}
  td, th {{ border: 1px solid #d0d7de; vertical-align: top; }}
  a {{ color: #0969da; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>{full_title}</h1>
<div class="meta">Generated: {generated} &nbsp;|&nbsp; Total: {len(results)}{_timing_html(start_time, now)}</div>
<div class="summary">{"".join(summary_parts)}</div>
<table>
<thead>
  <tr>
    <th>OVF Name</th>
    {vm_header}
    <th>Status</th>
    <th>Details</th>
  </tr>
</thead>
<tbody>
{"".join(rows_html)}
</tbody>
</table>
</body>
</html>
"""

    with open(report_path, "w") as f:
        f.write(html)

    # Print a plain-text summary to stdout
    print(f"\n{'='*60}")
    print(f"{title} — {generated}")
    print(f"{'='*60}")
    col = max((len(r.name) for r in results), default=10)
    for r in results:
        icon = _STATUS_STYLE.get(r.status, ("•",))[0]
        print(f"  {icon} {r.name:<{col}}  {r.status:<12}  {r.reason[:80]}")
    print(f"\n{'='*60}")
    for status, n in sorted(counts.items()):
        icon = _STATUS_STYLE.get(status, ("•",))[0]
        print(f"  {icon} {status}: {n}")
    print(f"\nReport written to {report_path}")


def vm_name_from_item(item_name: str) -> str:
    """
    Derive a short, K8s-safe VM name from the content library item name.

    K8s names must be lowercase alphanumeric or '-', max 63 chars.
    e.g. "BIGIP-16.0.1.1-0.0.6.ALL-vmware" -> "bigip"
         "bitnami-tomcatstack-8.0.36-x86_64" -> "bitnami-tomcatstack"
         "SLES11_SP2_64"                     -> "sles11"
    """
    # Lowercase and replace underscores with dashes
    name = item_name.lower().replace("_", "-")
    # Strip everything from the first version-like segment (digit after separator)
    name = re.split(r'[-.](\d)', name)[0]
    # Keep only alphanumeric and dashes, collapse consecutive dashes
    name = re.sub(r'[^a-z0-9-]', '-', name)
    name = re.sub(r'-+', '-', name).strip('-')
    # If nothing valid remains (e.g. all non-ASCII), use a generic prefix so the
    # UUID suffix produces a valid K8s name rather than one starting with a dash.
    if not name:
        name = "vm"
    # Truncate to 40 chars to leave room for suffix if needed
    return name[:40]



def _add_vcenter_args(parser: argparse.ArgumentParser) -> None:
    """Add common vCenter connection arguments to a subcommand parser."""
    parser.add_argument("--vcenter", required=True, help="vCenter hostname or IP")
    parser.add_argument("--vcenter-user", default=DEFAULT_VCENTER_USER,
                        help=f"vCenter username (default: {DEFAULT_VCENTER_USER})")
    parser.add_argument("--vcenter-password", required=True, help="vCenter password")
    parser.add_argument("--vcenter-root-password",
                        help="vCenter root SSH password for decryptK8Pwd.py (default: same as --vcenter-password)")


def cmd_discover(args: argparse.Namespace) -> int:
    """
    Discover OVF/OVA files from Artifactory and write a CSV ready for 'deploy'.

    Output format: name,url  (one entry per line, commented header included)
    """
    urls = discover_ovfs(args.base_url)
    if not urls:
        print("No OVF/OVA files found.")
        return 1

    entries = ovf_list_from_discovered(urls)

    out_path = args.output
    with open(out_path, 'w') as f:
        f.write(f"# OVF deploy list - generated from {args.base_url}\n")
        f.write("# Format: name,source[,config_file]\n")
        for entry in entries:
            f.write(f"{entry.name},{entry.source}\n")

    print(f"Wrote {len(entries)} entries to {out_path}")
    print(f"Edit the file to add a config_file column where needed, then run 'deploy'.")
    return 0



_TRANSIENT_UPLOAD_ERRORS = (
    "503",
    "service unavailable",
    "read timed out",
    "timed out",
    "connection reset",
    "504",
    "gateway timeout",
    "connectionerror",
    "connection aborted",
)

# Errors that are definitively permanent — file doesn't exist at source, corrupt disk, etc.
_PERMANENT_UPLOAD_ERRORS = (
    "was not found",
    "file not found",
    "no such file",
    "unable to parse disk image",
    "invalid sparse header",
    "invalid magic",
)


def _is_transient_upload_error(reason: str) -> bool:
    """Return True if the upload failure reason looks like a transient infrastructure error."""
    lower = reason.lower()
    # Permanent errors take priority — never retry these
    if any(pat in lower for pat in _PERMANENT_UPLOAD_ERRORS):
        return False
    return any(pat in lower for pat in _TRANSIENT_UPLOAD_ERRORS)


def _load_setup_state(csv_path: str, vcenter: str, content_library: str) -> dict:
    """
    Load the setup state file written by cmd_setup.
    Returns a dict mapping entry name -> {"status": ..., "transient": bool}.
    Returns empty dict if no state file exists.
    """
    safe_vc = vcenter.replace(":", "_").replace("/", "_")
    safe_lib = content_library.replace("/", "_")
    state_path = os.path.splitext(csv_path)[0] + f".setup-state.{safe_vc}.{safe_lib}.json"
    if not os.path.exists(state_path):
        return {}
    try:
        with open(state_path) as f:
            state = json.load(f)
        print(f"Loaded setup state from {state_path} ({len(state)} entries)")
        return state
    except Exception as e:
        print(f"Warning: could not read setup state {state_path}: {e}")
        return {}


DEFAULT_INFRA_TAG_CATEGORY = "ds"
DEFAULT_INFRA_TAG_NAME = "largedatastore"
DEFAULT_INFRA_DS_NAME = "nfsdatastore"
DEFAULT_INFRA_NFS_PATH = "/exports/nfsdatastore"
DEFAULT_INFRA_NFS_TYPE = "NFS41"
DEFAULT_INFRA_NFS_CONNECTIONS = 4
DEFAULT_INFRA_CL_MAX_CONCURRENT_SYNCS = 10
DEFAULT_INFRA_STORAGE_POLICY = "ovftest-policy"
DEFAULT_INFRA_NAMESPACE = DEFAULT_NAMESPACE
DEFAULT_INFRA_CONTENT_LIBRARY = DEFAULT_CONTENT_LIBRARY
DEFAULT_INFRA_VM_CLASS = DEFAULT_VM_CLASS


def cmd_setup_infra(args: argparse.Namespace) -> int:
    """
    Provision the vSphere infrastructure required for OVF deploy tests:

      1. Create tag category and tag for datastore classification
      2. Mount an NFS datastore on all hosts in the cluster
      3. Tag the datastore
      4. Create a VM storage policy selecting that tag
      5. Create a local content library
      6. Create a Supervisor namespace
      7-9. Assign storage policy, VM class, and content library to the namespace

    All steps are idempotent — already-existing objects are left unchanged.
    """
    vcenter = VCenterClient(
        args.vcenter, args.vcenter_user,
        args.vcenter_password,
    )
    try:
        vcenter.connect(ssh=False)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    try:
        cluster_name = args.cluster
        nfs_ip = args.nfs_ip
        tag_category = args.tag_category
        tag_name = args.tag_name
        ds_name = args.datastore_name
        nfs_path = args.nfs_path
        policy_name = args.storage_policy
        library_name = args.content_library
        namespace = args.namespace
        vm_class = args.vm_class

        print("\n=== Step 1: Ensure tag category and tag ===")
        cat_id = vcenter.ensure_tag_category(tag_category)
        tag_id = vcenter.ensure_tag(cat_id, tag_name)

        print("\n=== Step 2: Mount NFS datastore ===")
        ds_id = vcenter.ensure_nfs_datastore(cluster_name, nfs_ip, nfs_path, ds_name)

        print("\n=== Step 3: Tag the datastore ===")
        vcenter.attach_tag(tag_id, "Datastore", ds_id)

        print("\n=== Step 4: Create storage policy ===")
        policy_id = vcenter.ensure_storage_policy(policy_name, tag_category, tag_name)

        print("\n=== Step 5: Create content library ===")
        # Use the NFS datastore as backing for the content library
        lib_id = vcenter.ensure_local_content_library(library_name, ds_id)

        print("\n=== Step 5b: Configure content library concurrent sync limit ===")
        vcenter.set_content_library_max_concurrent_syncs(DEFAULT_INFRA_CL_MAX_CONCURRENT_SYNCS)

        print("\n=== Step 6-9: Create namespace and assign resources ===")
        cluster_id = vcenter.get_supervisor_cluster_id(cluster_name)
        vcenter.ensure_supervisor_namespace(
            namespace=namespace,
            cluster_id=cluster_id,
            storage_policy_id=policy_id,
            vm_class_name=vm_class,
            library_id=lib_id,
        )

        print("\n=== Infrastructure setup complete ===")
        print(f"  Tag category:    {tag_category} ({cat_id})")
        print(f"  Tag:             {tag_name} ({tag_id})")
        print(f"  NFS datastore:   {ds_name} ({ds_id})")
        print(f"  Storage policy:  {policy_name} ({policy_id})")
        print(f"  Content library: {library_name} ({lib_id})")
        print(f"  Namespace:       {namespace}")
        return 0

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        vcenter.disconnect()


def cmd_setup(args: argparse.Namespace) -> int:
    """Upload OVFs to a content library without deploying them.

    Maintains a state file (<csv>.setup-state.<vcenter>.<library>.json) so re-runs skip OVFs that
    previously failed with a permanent error (bad OVF, bad checksum, etc.) and
    only retry transient failures (503, timeout, connection reset, etc.).
    Delete the state file to force a full re-run.
    """
    entries = load_ovf_list(args.csv)
    if not entries:
        print(f"ERROR: No valid entries found in {args.csv}")
        return 1

    # State file: maps entry name -> {"status": ..., "reason": ..., "transient": bool}
    # Include vCenter IP and library name in the state file name so different
    # environments never share state.
    safe_vc = args.vcenter.replace(":", "_").replace("/", "_")
    safe_lib = args.content_library.replace("/", "_")
    state_path = os.path.splitext(args.csv)[0] + f".setup-state.{safe_vc}.{safe_lib}.json"
    state: dict = {}
    if os.path.exists(state_path):
        try:
            with open(state_path) as f:
                state = json.load(f)
            print(f"Loaded setup state from {state_path} ({len(state)} entries)")
        except Exception as e:
            print(f"Warning: could not read state file {state_path}: {e} — starting fresh")
            state = {}

    results: list[DeployResult] = []
    report_path = args.report or (os.path.splitext(args.csv)[0] + f".{safe_vc}.with-cl-setup.report.html")
    results_lock = threading.Lock()
    run_start = time.time()

    # Create a single shared vCenter connection for the entire run
    vcenter = VCenterClient(
        args.vcenter, args.vcenter_user,
        args.vcenter_password, args.vcenter_root_password,
    )
    try:
        vcenter.connect()
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    library_id = vcenter.find_content_library(args.content_library)
    if not library_id:
        print(f"ERROR: Content library '{args.content_library}' not found in vCenter")
        vcenter.disconnect()
        return 1

    print("Checking for stale update sessions from previous runs...")
    vcenter.cancel_stale_sessions(library_id)

    def record(result: DeployResult, transient: bool = False) -> None:
        with results_lock:
            results.append(result)
            state[result.name] = {
                "status": result.status,
                "reason": result.reason,
                "transient": transient,
            }
            try:
                with open(state_path, "w") as f:
                    json.dump(state, f, indent=2)
            except Exception as e:
                print(f"  Warning: could not write state file: {e}")
            write_report(results, report_path, start_time=run_start,
                         title="OVF Content Library Setup",
                         vcenter_ip=args.vcenter, show_vm_column=False)

    def setup_one(entry: OvfEntry, vc: VCenterClient) -> None:
        """Process a single OVF entry using the provided vCenter client."""
        prev = state.get(entry.name)
        is_permanent_failure = (
            prev and prev.get("status") == "SETUP_FAILED" and not prev.get("transient")
        )

        print(f"\n{'=' * 60}")
        print(f"Setup: {entry.name}  ({entry.source})")
        print(f"{'=' * 60}")

        try:
            # Always check CL first — a manually uploaded item overrides any prior state,
            # including permanent failures.
            existing = vc.find_library_item(library_id, entry.name)
            if existing:
                if existing["size"] > 0:
                    print(f"  Item present in content library ({existing['size']} bytes), marking SUCCESS")
                    record(DeployResult(
                        name=entry.name, source=entry.source, vm_name="",
                        status="SUCCESS", reason="Already present in content library"
                    ))
                    return
                else:
                    print(f"  Found 0-byte item in content library — deleting and re-uploading")
                    try:
                        vc.delete_library_item(existing["id"])
                    except Exception as _del_err:
                        print(f"  Warning: could not delete 0-byte item: {_del_err}")

            # Item not in CL. If this was a permanent failure, skip the upload attempt.
            if is_permanent_failure:
                prev_reason = prev.get('reason', '')
                if not prev_reason.startswith("[Permanent, not retried]"):
                    prev_reason = f"[Permanent, not retried] {prev_reason}"
                print(f"  Skipping upload — permanent failure from previous run: {prev_reason[:100]}")
                record(DeployResult(
                    name=entry.name, source=entry.source, vm_name="",
                    status="SETUP_FAILED",
                    reason=prev_reason
                ))
                return

            if prev and prev.get("status") == "SUCCESS":
                # State says SUCCESS but item is gone from CL — re-upload
                print(f"  State says SUCCESS but item missing from content library — re-uploading")

            try:
                vc.upload_ovf(library_id, entry.source, entry.name)
            except UntrustedSourceError as e:
                record(DeployResult(
                    name=entry.name, source=entry.source, vm_name="",
                    status="SETUP_FAILED",
                    reason=f"Upload failed: {e}"
                ))
                return
            except Exception as e:
                reason = str(e)
                transient = _is_transient_upload_error(reason)
                print(f"  Upload failed ({'transient' if transient else 'permanent'}): {reason[:120]}")
                record(DeployResult(
                    name=entry.name, source=entry.source, vm_name="",
                    status="SETUP_FAILED", reason=f"Upload failed: {reason}"
                ), transient=transient)
                return

            record(DeployResult(
                name=entry.name, source=entry.source, vm_name="",
                status="SUCCESS", reason="Uploaded to content library"
            ))

        except Exception as e:
            import traceback
            traceback.print_exc()
            reason = str(e)
            record(DeployResult(
                name=entry.name, source=entry.source, vm_name="",
                status="SETUP_FAILED", reason=reason
            ), transient=_is_transient_upload_error(reason))

    def setup_one_parallel(entry: OvfEntry) -> None:
        """Wrapper for parallel execution — creates its own vCenter client."""
        vc = VCenterClient(
            args.vcenter, args.vcenter_user,
            args.vcenter_password, args.vcenter_root_password,
        )
        try:
            vc.connect(ssh=False)
            setup_one(entry, vc)
        finally:
            vc.disconnect()

    workers = getattr(args, "parallel", 1)
    if workers > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(setup_one_parallel, entries))
    else:
        # Sequential mode: reuse the shared vcenter connection
        for entry in entries:
            setup_one(entry, vcenter)

    vcenter.disconnect()

    write_report(results, report_path, start_time=run_start,
                 title="OVF Content Library Setup",
                 vcenter_ip=args.vcenter, show_vm_column=False)

    transient_failures = [r for r in results if r.status == "SETUP_FAILED"
                          and state.get(r.name, {}).get("transient")]
    permanent_failures = [r for r in results if r.status == "SETUP_FAILED"
                          and not state.get(r.name, {}).get("transient")]
    if transient_failures:
        print(f"\n{len(transient_failures)} transient failure(s) — re-run setup to retry")
    if permanent_failures:
        print(f"{len(permanent_failures)} permanent failure(s) — will not be retried (delete {state_path} to force)")
    return 1 if any(r.status == "SETUP_FAILED" for r in results) else 0


def cmd_deploy(args: argparse.Namespace) -> int:
    """Deploy OVFs listed in a CSV file via VM Service."""
    entries = load_ovf_list(args.csv)
    if not entries:
        print(f"ERROR: No valid entries found in {args.csv}")
        return 1

    vcenter = None
    supervisor = None

    try:
        vcenter = VCenterClient(
            args.vcenter,
            args.vcenter_user,
            args.vcenter_password,
            args.vcenter_root_password
        )
        vcenter.connect()

        supervisor_ip, supervisor_password = vcenter.get_supervisor_credentials()
        if args.supervisor_root_password:
            supervisor_password = args.supervisor_root_password
            print("  Using provided Supervisor root password override")

        library_id = vcenter.find_content_library(args.content_library)
        if not library_id:
            print(f"ERROR: Content library '{args.content_library}' not found in vCenter")
            return 1

        supervisor = SupervisorClient(supervisor_ip, supervisor_password)
        supervisor.connect()

        if not supervisor.namespace_exists(args.namespace):
            print(f"ERROR: Namespace '{args.namespace}' does not exist")
            return 1
        print(f"Namespace '{args.namespace}' exists")

        libraries = supervisor.list_content_libraries(args.namespace)
        print(f"Content libraries in namespace: {libraries}")

        print(f"Purging existing VMs in namespace '{args.namespace}' before starting...")
        supervisor.delete_all_vms(args.namespace)

        results: list[DeployResult] = []
        _safe_vc = args.vcenter.replace(":", "_").replace("/", "_")
        report_path = args.report or (os.path.splitext(args.csv)[0] + f".{_safe_vc}.with-vmop.report.html")
        results_lock = threading.Lock()
        run_start = time.time()

        # Load setup state to skip permanently failed uploads
        setup_state = _load_setup_state(args.csv, args.vcenter, args.content_library)

        def record(result: DeployResult) -> None:
            with results_lock:
                results.append(result)
                write_report(results, report_path, start_time=run_start,
                             title="OVF Deploy with VM Service",
                             vcenter_ip=args.vcenter)

        def deploy_one(entry: OvfEntry, vc: VCenterClient, sv: SupervisorClient) -> None:
            """Process a single OVF entry using the provided clients."""
            import uuid as _uuid
            vm_name = vm_name_from_item(entry.name) + "-" + _uuid.uuid4().hex[:6]
            item_name = entry.name
            print(f"\n{'=' * 60}")
            print(f"Deploying: {entry.name}  ({entry.source})")
            print(f"{'=' * 60}")

            vm_created = False
            try:
                print(f"  Item name: '{item_name}' -> VM name: '{vm_name}'")

                if not args.cleanup:
                    # Pre-populated mode: only process entries that succeeded in setup
                    prev = setup_state.get(entry.name, {})
                    if prev.get("status") != "SUCCESS":
                        print(f"  Skipping — not in setup state as SUCCESS (status={prev.get('status', 'missing')})")
                        return
                    cl_check = vc.find_library_item(library_id, item_name)
                    if not cl_check or cl_check["size"] == 0:
                        print(f"  Skipping — item missing or empty in content library despite SUCCESS state")
                        return

                print("  Parsing OVF descriptor...")
                ovf_info = fetch_ovf_info(entry.source)
                if ovf_info:
                    if ovf_info.is_vapp:
                        print("    Type: vApp (VirtualSystemCollection)")
                        if getattr(args, "skip_vapps", False):
                            record(DeployResult(
                                name=entry.name, source=entry.source, vm_name=vm_name,
                                status="SKIPPED", reason="Multi-VM vApp skipped (--skip-vapps)"
                            ))
                            return
                    if ovf_info.has_networks():
                        print(f"    Networks: {[n.name for n in ovf_info.networks]}")
                    if ovf_info.has_properties():
                        print(f"    vApp properties: {len(ovf_info.properties)} keys")
                else:
                    print("    Warning: Could not parse OVF, proceeding without network/property info")

                vapp_config = None
                if entry.config_file:
                    vapp_config = load_vapp_config(entry.config_file)

                if args.cleanup:
                    # Self-contained mode: upload inline, delete CL item after test.
                    try:
                        vc.upload_ovf(library_id, entry.source, item_name)
                    except Exception as upload_err:
                        raise SetupError(f"Content library upload failed: {upload_err}") from upload_err

                vmi_name, vmi_error, failed_vmi_name = sv.wait_for_vmi(args.namespace, item_name)
                if not vmi_name:
                    search_terms = [t for t in [failed_vmi_name, item_name] if t]
                    logs = sv.get_vmop_logs(*search_terms)
                    record(DeployResult(
                        name=entry.name, source=entry.source, vm_name=vm_name,
                        status="FAILED",
                        reason=vmi_error or f"VirtualMachineImage for '{item_name}' never appeared",
                        vmop_logs=logs
                    ))
                    return

                _, _, rc = sv.run_kubectl(
                    f"get vm -n {args.namespace} {vm_name}", check=False
                )
                if rc == 0:
                    print(f"  VM '{vm_name}' already exists, deleting...")
                    sv.delete_vm(args.namespace, vm_name)
                    for _ in range(30):
                        _, _, rc = sv.run_kubectl(
                            f"get vm -n {args.namespace} {vm_name}", check=False
                        )
                        if rc != 0:
                            break
                        time.sleep(5)
                    else:
                        print("  Warning: VM deletion timed out, proceeding anyway")

                vm_start_time = time.time()
                sv.create_vm(
                    namespace=args.namespace,
                    vm_name=vm_name,
                    image_name=vmi_name,
                    vm_class=args.vm_class,
                    storage_class=args.storage_class,
                    ovf_info=ovf_info,
                    network_type=args.network_type,
                    vapp_config=vapp_config,
                )
                vm_created = True

                powered_on, _ = sv.wait_for_vm_powered_on(args.namespace, vm_name, vcenter=vc)

                if powered_on:
                    record(DeployResult(
                        name=entry.name, source=entry.source, vm_name=vm_name,
                        status="SUCCESS", reason="VM powered on"
                    ))
                else:
                    elapsed = int(time.time() - vm_start_time) + 30
                    reason = sv.get_vm_status_reason(args.namespace, vm_name)
                    logs = sv.get_vmop_logs_for_vm(vm_name, since_seconds=elapsed)
                    record(DeployResult(
                        name=entry.name, source=entry.source, vm_name=vm_name,
                        status="FAILED",
                        reason=f"VM did not reach Running phase within timeout. {reason}",
                        vmop_logs=logs
                    ))

            except UntrustedSourceError:
                print(f"  Skipping: source server TLS certificate could not be trusted by vCenter")
                record(DeployResult(
                    name=entry.name, source=entry.source, vm_name=vm_name,
                    status="SKIPPED", reason="Source TLS certificate could not be added to vCenter trust store"
                ))

            except SetupError as e:
                print(f"  Setup failed: {e}")
                record(DeployResult(
                    name=entry.name, source=entry.source, vm_name=vm_name,
                    status="SETUP_FAILED", reason=str(e)
                ))

            except Exception as e:
                import traceback
                traceback.print_exc()
                try:
                    logs = sv.get_vmop_logs_for_vm(vm_name)
                    reason_from_cr = sv.get_vm_status_reason(args.namespace, vm_name)
                except Exception:
                    logs, reason_from_cr = "", ""
                reason = str(e)
                if reason_from_cr:
                    reason += f". CR: {reason_from_cr}"
                record(DeployResult(
                    name=entry.name, source=entry.source, vm_name=vm_name,
                    status="FAILED", reason=reason, vmop_logs=logs
                ))

            finally:
                if vm_created and not args.no_cleanup_vm:
                    try:
                        sv.delete_vm(args.namespace, vm_name)
                    except Exception as e:
                        print(f"  Warning: VM deletion failed: {e}")
                elif vm_created and args.no_cleanup_vm:
                    print(f"  VM '{vm_name}' left running for inspection (--no-cleanup-vm)")
                if args.cleanup and not args.no_cleanup_cl:
                    try:
                        cl_item = vc.find_library_item(library_id, item_name)
                        if cl_item:
                            vc.delete_library_item(cl_item["id"])
                            print(f"  Deleted content library item '{item_name}'")
                    except Exception as e:
                        print(f"  Warning: CL item deletion failed: {e}")

        def deploy_one_parallel(entry: OvfEntry) -> None:
            """Wrapper for parallel execution — creates its own clients."""
            vc = VCenterClient(
                args.vcenter, args.vcenter_user,
                args.vcenter_password, args.vcenter_root_password
            )
            sv = SupervisorClient(supervisor_ip, supervisor_password)
            try:
                vc.connect()
                sv.connect()
                deploy_one(entry, vc, sv)
            finally:
                vc.disconnect()
                sv.disconnect()

        workers = getattr(args, "parallel", 1)
        if workers > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(deploy_one_parallel, entries))
        else:
            # Sequential mode: reuse the shared connections
            for entry in entries:
                deploy_one(entry, vcenter, supervisor)

        write_report(results, report_path, start_time=run_start,
                     title="OVF Deploy with VM Service",
                     vcenter_ip=args.vcenter)  # final write also prints summary to stdout
        return 1 if any(r.status in ("FAILED", "SETUP_FAILED") for r in results) else 0

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if supervisor:
            supervisor.disconnect()
        if vcenter:
            vcenter.disconnect()


def cmd_validate(args: argparse.Namespace) -> int:
    """
    Validate OVFs by uploading to a content library and deploying directly via
    vSphere API (no VM Service / Supervisor required). Each VM is deleted after
    the test regardless of outcome.
    """
    entries = load_ovf_list(args.csv)
    if not entries:
        print(f"ERROR: No valid entries found in {args.csv}")
        return 1

    _safe_vc = args.vcenter.replace(":", "_").replace("/", "_")
    report_path = args.report or (os.path.splitext(args.csv)[0] + f".{_safe_vc}.with-cl.report.html")
    results: list[DeployResult] = []
    results_lock = threading.Lock()
    run_start = time.time()

    # Load setup state to skip permanently failed uploads and avoid re-uploading
    setup_state = _load_setup_state(args.csv, args.vcenter, args.content_library)

    def record(result: DeployResult) -> None:
        with results_lock:
            results.append(result)
            write_report(results, report_path, start_time=run_start,
                         title="OVF Deploy with Content Library",
                         vcenter_ip=args.vcenter)

    vcenter: Optional[VCenterClient] = None
    try:
        vcenter = VCenterClient(
            args.vcenter,
            args.vcenter_user,
            args.vcenter_password,
            args.vcenter_root_password,
        )
        vcenter.connect(ssh=False)

        library_id = vcenter.find_content_library(args.content_library)
        if not library_id:
            print(f"ERROR: Content library '{args.content_library}' not found")
            return 1

        target = vcenter.get_default_deploy_target(
            datacenter=args.datacenter,
            cluster=args.cluster,
            datastore=args.datastore,
            resource_pool=args.resource_pool,
        )

        def validate_one(entry: OvfEntry, vc: VCenterClient) -> None:
            """Process a single OVF entry using the provided vCenter client."""
            import uuid as _uuid
            vm_name_base = vm_name_from_item(entry.name)
            vm_name = vm_name_base + "-" + _uuid.uuid4().hex[:6]
            item_name = entry.name
            print(f"\n[{entry.name}] source={entry.source}")

            resource_id: Optional[str] = None
            resource_type: str = "VirtualMachine"
            try:
                if args.cleanup:
                    # Self-contained mode: upload inline, delete CL item after test
                    try:
                        vc.upload_ovf(library_id, entry.source, item_name)
                    except Exception as e:
                        record(DeployResult(
                            name=entry.name, source=entry.source, vm_name=vm_name,
                            status="SETUP_FAILED",
                            reason=f"Content library upload failed: {e}"
                        ))
                        return
                    cl_item = vc.find_library_item(library_id, item_name)
                else:
                    # Pre-populated mode: only process entries that succeeded in setup
                    prev = setup_state.get(entry.name, {})
                    if prev.get("status") != "SUCCESS":
                        print(f"  Skipping — not in setup state as SUCCESS (status={prev.get('status', 'missing')})")
                        return
                    cl_item = vc.find_library_item(library_id, item_name)
                    if not cl_item or cl_item["size"] == 0:
                        print(f"  Skipping — item missing or empty in content library despite SUCCESS state")
                        return

                if not cl_item:
                    record(DeployResult(
                        name=entry.name, source=entry.source, vm_name=vm_name,
                        status="FAILED", reason="Library item not found after upload"
                    ))
                    return

                vc.delete_existing_by_name(vm_name)
                for _deploy_attempt in range(5):
                    try:
                        resource_id, resource_type = vc.deploy_library_item(
                            cl_item["id"], vm_name,
                            target["resource_pool_id"],
                            target["folder_id"],
                            target["datastore_id"],
                        )
                        break
                    except RuntimeError as _deploy_err:
                        if "already exists" in str(_deploy_err) and _deploy_attempt < 4:
                            import uuid as _uuid
                            vm_name = vm_name_base + "-" + _uuid.uuid4().hex[:8]
                            print(f"  Name collision on deploy, retrying with new name: {vm_name}")
                            vc.delete_existing_by_name(vm_name)
                        else:
                            raise

                if resource_type == "VirtualApp":
                    vc.power_on_vapp_by_id(resource_id)
                    powered_on = vc.wait_for_vapp_powered_on_by_id(resource_id)
                else:
                    vc.power_on_vm_by_id(resource_id)
                    powered_on = vc.wait_for_vm_powered_on_by_id(resource_id)

                if powered_on:
                    record(DeployResult(
                        name=entry.name, source=entry.source, vm_name=vm_name,
                        status="SUCCESS", reason=f"{resource_type} powered on"
                    ))
                else:
                    record(DeployResult(
                        name=entry.name, source=entry.source, vm_name=vm_name,
                        status="FAILED",
                        reason=f"{resource_type} did not reach PoweredOn state within timeout"
                    ))

            except Exception as e:
                import traceback
                traceback.print_exc()
                record(DeployResult(
                    name=entry.name, source=entry.source, vm_name=vm_name,
                    status="FAILED", reason=str(e)
                ))
            finally:
                if resource_id:
                    if not args.no_cleanup_vm:
                        if resource_type == "VirtualApp":
                            vc.delete_vapp_by_id(resource_id)
                        else:
                            vc.delete_vm_by_id(resource_id)
                    else:
                        print(f"  VM/vApp '{vm_name}' left running for inspection (--no-cleanup-vm)")
                if args.cleanup:
                    # In --cleanup mode, delete the CL item we uploaded inline
                    try:
                        cl_item_to_del = vc.find_library_item(library_id, item_name)
                        if cl_item_to_del:
                            vc.delete_library_item(cl_item_to_del["id"])
                    except Exception as _del_err:
                        print(f"  Warning: could not delete CL item '{item_name}': {_del_err}")

        def validate_one_parallel(entry: OvfEntry) -> None:
            """Wrapper for parallel execution — creates its own vCenter client."""
            vc = VCenterClient(
                args.vcenter, args.vcenter_user,
                args.vcenter_password, args.vcenter_root_password,
            )
            try:
                vc.connect(ssh=False)
                validate_one(entry, vc)
            finally:
                vc.disconnect()

        workers = getattr(args, "parallel", 1)
        if workers > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(validate_one_parallel, entries))
        else:
            # Sequential mode: reuse the shared vcenter connection
            for entry in entries:
                validate_one(entry, vcenter)

        write_report(results, report_path, start_time=run_start,
                     title="OVF Deploy with Content Library",
                     vcenter_ip=args.vcenter)
        return 1 if any(r.status in ("FAILED", "SETUP_FAILED") for r in results) else 0

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if vcenter:
            vcenter.disconnect()


@dataclass
class VmiStatusResult:
    """Status of a single OVF's VirtualMachineImage on the Supervisor."""
    name: str          # OVF name (from state file)
    source: str        # OVF source URL
    vmi_name: str      # VMI CR name, empty if not found
    vmi_uid: str       # VMI UID, empty if not found
    status: str        # READY / NOT_READY / NOT_FOUND
    reason: str        # Human-readable condition message or explanation


def _fetch_vmi_results(supervisor: "SupervisorClient", namespace: str,
                       cl_entries: dict, ovf_entries: dict) -> list[VmiStatusResult]:
    """
    Fetch all VMIs from the Supervisor and match them against cl_entries.
    Returns a list of VmiStatusResult, one per CL entry.
    """
    stdout, _, rc = supervisor.run_kubectl(
        f"get vmi -n {namespace} -o json", check=False
    )
    if rc != 0 or not stdout.strip():
        raise RuntimeError("Could not list VMIs from Supervisor")

    vmi_list = json.loads(stdout).get("items", [])

    # Build lookup: lowercase cr name / display name -> vmi item
    vmi_by_name: dict[str, dict] = {}
    for item in vmi_list:
        vmi_cr_name = item.get("metadata", {}).get("name", "")
        display_name = item.get("status", {}).get("name", "")
        if vmi_cr_name:
            vmi_by_name[vmi_cr_name.lower()] = item
        if display_name:
            vmi_by_name[display_name.lower()] = item

    results: list[VmiStatusResult] = []
    for name in sorted(cl_entries):
        entry = ovf_entries.get(name)
        source = entry.source if entry else ""

        # Find matching VMI — exact name first, then substring
        matched_item = vmi_by_name.get(name.lower())
        if not matched_item:
            for vmi_item in vmi_list:
                vmi_cr_name = vmi_item.get("metadata", {}).get("name", "")
                display_name = vmi_item.get("status", {}).get("name", "")
                if (name.lower() in vmi_cr_name.lower() or
                        name.lower() in display_name.lower()):
                    matched_item = vmi_item
                    break

        if not matched_item:
            results.append(VmiStatusResult(
                name=name, source=source,
                vmi_name="", vmi_uid="",
                status="NOT_FOUND",
                reason="No VirtualMachineImage found in namespace",
            ))
            continue

        vmi_cr_name = matched_item.get("metadata", {}).get("name", "")
        vmi_uid = matched_item.get("metadata", {}).get("uid", "")
        conditions = matched_item.get("status", {}).get("conditions", [])
        ready_cond = next((c for c in conditions if c.get("type") == "Ready"), None)

        if ready_cond and ready_cond.get("status") == "True":
            results.append(VmiStatusResult(
                name=name, source=source,
                vmi_name=vmi_cr_name, vmi_uid=vmi_uid,
                status="READY",
                reason=ready_cond.get("message", ""),
            ))
        else:
            reason = ""
            if ready_cond:
                reason = ready_cond.get("message", "") or ready_cond.get("reason", "")
            results.append(VmiStatusResult(
                name=name, source=source,
                vmi_name=vmi_cr_name, vmi_uid=vmi_uid,
                status="NOT_READY",
                reason=reason or "Ready condition not True",
            ))

    return results


def cmd_check_vmi_status(args: argparse.Namespace) -> int:
    """
    Check VirtualMachineImage readiness for all OVFs uploaded to the content library.

    Uses the setup-state JSON as the source of truth for which OVFs are in the
    content library (SUCCESS entries only), then queries the Supervisor for their
    corresponding VMI CRs and reports Ready / Not Ready / Not Found.

    With --wait, polls until all VMIs are Ready or the timeout expires.
    """
    # Load setup state — source of truth for what's in the CL
    if getattr(args, "state_file", None):
        try:
            with open(args.state_file) as f:
                setup_state = json.load(f)
            print(f"Loaded setup state from {args.state_file} ({len(setup_state)} entries)")
        except Exception as e:
            print(f"ERROR: Could not read state file {args.state_file}: {e}")
            return 1
    else:
        setup_state = _load_setup_state(args.csv, args.vcenter, args.content_library)
    if not setup_state:
        print(f"ERROR: No setup state found for {args.csv} / {args.vcenter} / {args.content_library}")
        print("Run 'setup-cl' first to populate the content library.")
        return 1

    cl_entries = {name: info for name, info in setup_state.items()
                  if info.get("status") == "SUCCESS"}
    if not cl_entries:
        print("No SUCCESS entries in setup state — nothing to check.")
        return 1
    print(f"Checking VMI status for {len(cl_entries)} CL entries...")

    # Load CSV to get source URLs for report links
    ovf_entries = {e.name: e for e in load_ovf_list(args.csv)}

    wait_mode = getattr(args, "wait", False)
    wait_timeout = getattr(args, "wait_timeout", VMI_WAIT_TIMEOUT)
    wait_interval = getattr(args, "wait_interval", 30)

    vcenter = None
    supervisor = None
    try:
        vcenter = VCenterClient(
            args.vcenter, args.vcenter_user,
            args.vcenter_password, args.vcenter_root_password,
        )
        vcenter.connect(ssh=False)
        vcenter._create_ssh_session()

        supervisor_ip, supervisor_password = vcenter.get_supervisor_credentials()
        supervisor = SupervisorClient(supervisor_ip, supervisor_password)
        supervisor.connect()

        _safe_vc = args.vcenter.replace(":", "_").replace("/", "_")
        report_path = args.report or (
            os.path.splitext(args.csv)[0] + f".{_safe_vc}.vmi-status.report.html"
        )
        run_start = time.time()

        print(f"Fetching VMIs in namespace '{args.namespace}'...")
        results = _fetch_vmi_results(supervisor, args.namespace, cl_entries, ovf_entries)
        _write_vmi_report(results, report_path, run_start, args.vcenter)

        if not wait_mode:
            return 0

        # --wait: poll until all VMIs are Ready or timeout
        deadline = run_start + wait_timeout
        poll = 0
        while True:
            not_ready = [r for r in results if r.status != "READY"]
            if not not_ready:
                print(f"\nAll {len(results)} VMIs are Ready.")
                return 0

            elapsed = int(time.time() - run_start)
            remaining = int(deadline - time.time())
            if remaining <= 0:
                print(f"\nTimeout after {elapsed}s — "
                      f"{len(not_ready)} VMI(s) still not Ready:")
                for r in not_ready:
                    print(f"  {r.name}: {r.status} — {r.reason[:80]}")
                return 1

            poll += 1
            not_ready_names = ", ".join(r.name for r in not_ready[:5])
            if len(not_ready) > 5:
                not_ready_names += f" (+{len(not_ready) - 5} more)"
            print(f"\n[{elapsed}s elapsed, {remaining}s remaining] "
                  f"{len(not_ready)} not Ready: {not_ready_names}")
            print(f"  Next check in {wait_interval}s...")
            time.sleep(wait_interval)

            print(f"Fetching VMIs in namespace '{args.namespace}'...")
            results = _fetch_vmi_results(supervisor, args.namespace, cl_entries, ovf_entries)
            _write_vmi_report(results, report_path, run_start, args.vcenter)

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if supervisor:
            supervisor.disconnect()
        if vcenter:
            vcenter.disconnect()


_VMI_STATUS_STYLE = {
    "READY":     ("✅", "#1a7f37", "#dafbe1"),
    "NOT_READY": ("⚠️",  "#9a6700", "#fff8c5"),
    "NOT_FOUND": ("❌", "#cf222e", "#ffebe9"),
}


def _write_vmi_report(results: list[VmiStatusResult], report_path: str,
                      start_time: Optional[float], vcenter_ip: str) -> None:
    """Write an HTML VMI status report and print a summary to stdout."""
    now = time.time()
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    title = "VMI Status Report"
    full_title = f"{title} — {vcenter_ip}" if vcenter_ip else title

    rows_html = []
    for r in results:
        icon, fg, bg = _VMI_STATUS_STYLE.get(r.status, ("•", "#24292f", "#f6f8fa"))
        name_cell = (
            f'<a href="{_html_escape(r.source)}" target="_blank">{_html_escape(r.name)}</a>'
            if r.source.startswith("http")
            else _html_escape(r.name)
        )
        badge = (
            f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
            f'background:{bg};color:{fg};font-weight:600;font-size:0.85em;'
            f'border:1px solid {fg}33;">{icon} {_html_escape(r.status)}</span>'
        )
        vmi_cell = (
            f'<span style="font-family:monospace;font-size:0.85em;">{_html_escape(r.vmi_name)}</span>'
            f'<br><span style="font-size:0.75em;color:#57606a;">{_html_escape(r.vmi_uid)}</span>'
            if r.vmi_name else '<span style="color:#57606a;font-size:0.85em;">—</span>'
        )
        rows_html.append(
            f"<tr>"
            f'<td style="padding:8px 12px;">{name_cell}</td>'
            f'<td style="padding:8px 12px;">{vmi_cell}</td>'
            f'<td style="padding:8px 12px;text-align:center;">{badge}</td>'
            f'<td style="padding:8px 12px;font-size:0.85em;color:#24292f;">{_html_escape(r.reason)}</td>'
            f"</tr>"
        )

    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    summary_parts = []
    for status, (icon, fg, _bg) in _VMI_STATUS_STYLE.items():
        n = counts.get(status, 0)
        if n:
            summary_parts.append(
                f'<span style="margin-right:16px;color:{fg};font-weight:600;">'
                f'{icon} {status}: {n}</span>'
            )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{full_title} — {generated}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         margin: 32px; color: #24292f; background: #fff; }}
  h1   {{ font-size: 1.4em; margin-bottom: 4px; }}
  .meta {{ color: #57606a; font-size: 0.85em; margin-bottom: 20px; }}
  .summary {{ margin-bottom: 20px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.9em; }}
  thead th {{ background: #f6f8fa; border-bottom: 2px solid #d0d7de;
              padding: 8px 12px; text-align: left; font-weight: 600; }}
  tbody tr:nth-child(even) {{ background: #f6f8fa; }}
  tbody tr:hover {{ background: #eaf5ff; }}
  td, th {{ border: 1px solid #d0d7de; vertical-align: top; }}
  a {{ color: #0969da; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>{full_title}</h1>
<div class="meta">Generated: {generated} &nbsp;|&nbsp; Total: {len(results)}{_timing_html(start_time, now)}</div>
<div class="summary">{"".join(summary_parts)}</div>
<table>
<thead>
  <tr>
    <th>OVF Name</th>
    <th>VMI Name / UID</th>
    <th>Status</th>
    <th>Reason</th>
  </tr>
</thead>
<tbody>
{"".join(rows_html)}
</tbody>
</table>
</body>
</html>
"""
    with open(report_path, "w") as f:
        f.write(html)

    print(f"\n{'='*60}")
    print(f"{full_title} — {generated}")
    print(f"{'='*60}")
    col = max((len(r.name) for r in results), default=10)
    for r in results:
        icon = _VMI_STATUS_STYLE.get(r.status, ("•",))[0]
        print(f"  {icon} {r.name:<{col}}  {r.status:<10}  {r.reason[:80]}")
    print(f"\n{'='*60}")
    for status, n in sorted(counts.items()):
        icon = _VMI_STATUS_STYLE.get(status, ("•",))[0]
        print(f"  {icon} {status}: {n}")
    print(f"\nReport written to {report_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OVF deploy test tool for VM Service on Supervisor"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- discover subcommand ---
    p_discover = sub.add_parser(
        "discover",
        help="Discover OVF/OVA files from Artifactory and write a deploy CSV"
    )
    p_discover.add_argument(
        "output",
        help="Path to write the CSV file (e.g. ovfs.csv)"
    )
    p_discover.add_argument(
        "--base-url",
        default=DEFAULT_OVF_BASE_URL,
        help=f"Artifactory base URL to discover from (default: {DEFAULT_OVF_BASE_URL})"
    )

    # --- deploy subcommand ---
    p_deploy = sub.add_parser(
        "deploy",
        help="Deploy OVFs from a CSV file via VM Service"
    )
    p_deploy.add_argument(
        "csv",
        help="CSV file with OVFs to deploy (name,source[,config_file])"
    )
    _add_vcenter_args(p_deploy)
    p_deploy.add_argument(
        "--supervisor-root-password",
        help="Override Supervisor root SSH password (default: retrieved from vCenter)"
    )
    p_deploy.add_argument(
        "--namespace",
        default=DEFAULT_NAMESPACE,
        help=f"Target namespace (default: {DEFAULT_NAMESPACE})"
    )
    p_deploy.add_argument(
        "--content-library",
        default=DEFAULT_CONTENT_LIBRARY,
        help=f"Content library name (default: {DEFAULT_CONTENT_LIBRARY})"
    )
    p_deploy.add_argument(
        "--vm-class",
        default=DEFAULT_VM_CLASS,
        help=f"VM class to use (default: {DEFAULT_VM_CLASS})"
    )
    p_deploy.add_argument(
        "--storage-class",
        default=STORAGE_CLASS,
        help=f"Storage class for VM disks (default: {STORAGE_CLASS})"
    )
    p_deploy.add_argument(
        "--network-type",
        choices=["nsx", "vds"],
        default="nsx",
        help="Network type: 'nsx' (SubnetSet) or 'vds' (Network) (default: nsx)"
    )
    p_deploy.add_argument(
        "--cleanup", "--clean-up",
        action="store_true",
        help="Delete each VM after deployment (errors ignored)"
    )
    p_deploy.add_argument(
        "--no-cleanup-cl",
        action="store_true",
        help="When --cleanup is set, skip deleting the content library item"
    )
    p_deploy.add_argument(
        "--no-cleanup-vm",
        action="store_true",
        help="Leave VMs running after the test instead of deleting them (useful for inspection)"
    )
    p_deploy.add_argument(
        "--skip-vapps",
        action="store_true",
        help="Skip multi-VM vApp OVFs (VirtualSystemCollection) instead of attempting deployment"
    )
    p_deploy.add_argument(
        "--parallel",
        type=int,
        default=1,
        metavar="N",
        help="Number of OVFs to deploy concurrently (default: 1)"
    )
    p_deploy.add_argument(
        "--report",
        help="Path to write the results report (default: <csv>.<vcenter>.with-vmop.report.html)"
    )

    # --- setup-infra subcommand ---
    p_setup_infra = sub.add_parser(
        "setup-infra",
        help="Provision vSphere infrastructure (NFS datastore, tag, storage policy, namespace) for OVF tests"
    )
    p_setup_infra.add_argument("--vcenter", required=True, help="vCenter hostname or IP")
    p_setup_infra.add_argument("--vcenter-user", default=DEFAULT_VCENTER_USER,
                               help=f"vCenter username (default: {DEFAULT_VCENTER_USER})")
    p_setup_infra.add_argument("--vcenter-password", required=True, help="vCenter password")
    p_setup_infra.add_argument("--cluster", required=True,
                               help="vSphere cluster name to mount the NFS datastore on")
    p_setup_infra.add_argument("--nfs-ip", required=True,
                               help="NFS server IP address")
    p_setup_infra.add_argument("--nfs-path", default=DEFAULT_INFRA_NFS_PATH,
                               help=f"NFS export path (default: {DEFAULT_INFRA_NFS_PATH})")
    p_setup_infra.add_argument("--datastore-name", default=DEFAULT_INFRA_DS_NAME,
                               help=f"Name for the NFS datastore (default: {DEFAULT_INFRA_DS_NAME})")
    p_setup_infra.add_argument("--tag-category", default=DEFAULT_INFRA_TAG_CATEGORY,
                               help=f"Tag category name (default: {DEFAULT_INFRA_TAG_CATEGORY})")
    p_setup_infra.add_argument("--tag-name", default=DEFAULT_INFRA_TAG_NAME,
                               help=f"Tag name (default: {DEFAULT_INFRA_TAG_NAME})")
    p_setup_infra.add_argument("--storage-policy", default=DEFAULT_INFRA_STORAGE_POLICY,
                               help=f"Storage policy name (default: {DEFAULT_INFRA_STORAGE_POLICY})")
    p_setup_infra.add_argument("--content-library", default=DEFAULT_INFRA_CONTENT_LIBRARY,
                               help=f"Content library name (default: {DEFAULT_INFRA_CONTENT_LIBRARY})")
    p_setup_infra.add_argument("--namespace", default=DEFAULT_INFRA_NAMESPACE,
                               help=f"Supervisor namespace name (default: {DEFAULT_INFRA_NAMESPACE})")
    p_setup_infra.add_argument("--vm-class", default=DEFAULT_INFRA_VM_CLASS,
                               help=f"VM class to assign to the namespace (default: {DEFAULT_INFRA_VM_CLASS})")

    # --- setup-cl subcommand ---
    p_setup = sub.add_parser(
        "setup-cl",
        help="Upload OVFs to a content library (run before deploy/validate to isolate upload failures)"
    )
    p_setup.add_argument(
        "csv",
        help="CSV file with OVFs to upload (name,source[,config_file])"
    )
    _add_vcenter_args(p_setup)
    p_setup.add_argument(
        "--content-library",
        default=DEFAULT_CONTENT_LIBRARY,
        help=f"Content library name (default: {DEFAULT_CONTENT_LIBRARY})"
    )
    p_setup.add_argument(
        "--parallel",
        type=int,
        default=1,
        metavar="N",
        help="Number of OVFs to upload concurrently (default: 1)"
    )
    p_setup.add_argument(
        "--report",
        help="Path to write the results report (default: <csv>.with-cl-setup.report.html)"
    )

    # --- check-vmi-status subcommand ---
    p_vmi = sub.add_parser(
        "check-vmi-status",
        help="Check VirtualMachineImage readiness for all OVFs in the content library"
    )
    p_vmi.add_argument(
        "csv",
        help="CSV file used for setup-cl (to resolve source URLs and state file path)"
    )
    _add_vcenter_args(p_vmi)
    p_vmi.add_argument(
        "--namespace",
        default=DEFAULT_NAMESPACE,
        help=f"Supervisor namespace to query VMIs from (default: {DEFAULT_NAMESPACE})"
    )
    p_vmi.add_argument(
        "--content-library",
        default=DEFAULT_CONTENT_LIBRARY,
        help=f"Content library name (used to locate the state file) (default: {DEFAULT_CONTENT_LIBRARY})"
    )
    p_vmi.add_argument(
        "--state-file",
        help="Path to the setup-state JSON file (default: <csv>.setup-state.<vcenter>.<library>.json)"
    )
    p_vmi.add_argument(
        "--wait",
        action="store_true",
        help="Poll until all VMIs are Ready or --wait-timeout is reached"
    )
    p_vmi.add_argument(
        "--wait-timeout",
        type=int,
        default=VMI_WAIT_TIMEOUT,
        metavar="SECONDS",
        help=f"Maximum time to wait for all VMIs to become Ready (default: {VMI_WAIT_TIMEOUT}s)"
    )
    p_vmi.add_argument(
        "--wait-interval",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Polling interval when --wait is set (default: 30s)"
    )
    p_vmi.add_argument(
        "--report",
        help="Path to write the HTML report (default: <csv>.<vcenter>.vmi-status.report.html)"
    )

    # --- validate subcommand ---
    p_validate = sub.add_parser(
        "validate",
        help="Validate OVFs by deploying directly via vSphere API (no Supervisor needed)"
    )
    p_validate.add_argument(
        "csv",
        help="CSV file with OVFs to validate (name,source[,config_file])"
    )
    _add_vcenter_args(p_validate)
    p_validate.add_argument(
        "--content-library",
        default=DEFAULT_CONTENT_LIBRARY,
        help=f"Content library name to use for staging (default: {DEFAULT_CONTENT_LIBRARY})"
    )
    p_validate.add_argument(
        "--datacenter",
        default=None,
        help="Datacenter name to deploy into (default: first available)"
    )
    p_validate.add_argument(
        "--cluster",
        default=None,
        help="Cluster name to deploy into (default: first available)"
    )
    p_validate.add_argument(
        "--datastore",
        default=None,
        help="Datastore name to deploy into (default: first writable)"
    )
    p_validate.add_argument(
        "--resource-pool",
        default=None,
        help="Resource pool name to deploy into (default: cluster root resource pool)"
    )
    p_validate.add_argument(
        "--parallel",
        type=int,
        default=1,
        metavar="N",
        help="Number of OVFs to validate concurrently (default: 1)"
    )
    p_validate.add_argument(
        "--report",
        help="Path to write the results report (default: <csv>.with-cl.report.html)"
    )
    p_validate.add_argument(
        "--cleanup", "--clean-up",
        action="store_true",
        help="Upload OVFs inline and delete CL item after test (default: use pre-populated CL from 'setup')"
    )
    p_validate.add_argument(
        "--no-cleanup-vm",
        action="store_true",
        help="Leave VMs running after the test instead of deleting them (useful for inspection)"
    )

    args = parser.parse_args()

    if args.command == "discover":
        return cmd_discover(args)
    elif args.command == "setup-infra":
        return cmd_setup_infra(args)
    elif args.command == "setup-cl":
        return cmd_setup(args)
    elif args.command == "check-vmi-status":
        return cmd_check_vmi_status(args)
    elif args.command == "validate":
        return cmd_validate(args)
    else:
        return cmd_deploy(args)


if __name__ == "__main__":
    sys.exit(main())