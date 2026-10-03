"""
Read-only truth detector.

For each spoofable identifier, reads every consumer path that applications
might query. Reports the value each path returns and flags any disagreement.

Important distinction:
  - Some sources are "copies" of the same identifier (MAC in different formats).
    These SHOULD agree, and the module flags disagreement.
  - Some sources are DIFFERENT identifiers that happen to look alike
    (MachineGuid vs SQMClient MachineId vs SMBIOS UUID).
    These are listed without comparison.

This module NEVER writes. It is safe to run on any system.
"""
import re
from typing import Any

import winreg

from core import registry
from core.logger import log
from core.powershell import run_quiet
from modules.base import SpoofModule


NET_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
MACHINE_GUID_KEY = r"SOFTWARE\Microsoft\Cryptography"
SQM_CLIENT_KEY = r"SOFTWARE\Microsoft\SQMClient"
ONESETTINGS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\DeviceAttributes"
COMPUTERNAME_KEY = r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
ACTIVE_COMPUTERNAME_KEY = r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
TCPIP_INTERFACES = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
TCPIP_PARAMETERS = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

_GUID_RE = re.compile(
    r"^\{?[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}?$"
)


def _normalize(value: Any) -> str:
    """
    Normalize a value for comparison purposes.

    - Strips whitespace
    - Uppercases
    - MAC-shaped strings (12 hex with any of ':', '-', or none) -> bare 12 hex
    - GUID-shaped strings (with or without braces) -> bare GUID, uppercased
    """
    if value is None:
        return ""
    v = str(value).strip().upper()

    # MAC normalization: strip all non-hex and check length
    hex_only = re.sub(r"[^0-9A-F]", "", v)
    if len(hex_only) == 12:
        return hex_only

    # GUID normalization: strip braces
    if _GUID_RE.match(v):
        return v.strip("{}")

    return v


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def _reg(root: int, path: str, value: str) -> str:
    try:
        v = registry.read_value(root, path, value)
        return str(v) if v is not None else "<absent>"
    except Exception as e:
        return f"<err: {e}>"


def _ps(script: str) -> str:
    out = run_quiet(script)
    return out.strip() if out else "<empty>"


def _find_mac_subkey(adapter_desc: str) -> str | None:
    """Locate registry subkey whose DriverDesc == adapter_desc (case-insensitive)."""
    for subkey in registry.enum_subkeys(winreg.HKEY_LOCAL_MACHINE, NET_CLASS_KEY):
        if not subkey.isdigit():
            continue
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                f"{NET_CLASS_KEY}\\{subkey}",
                0,
                winreg.KEY_READ,
            ) as k:
                desc, _ = winreg.QueryValueEx(k, "DriverDesc")
            if desc.lower() == adapter_desc.lower():
                return subkey
        except (FileNotFoundError, OSError):
            continue
    return None


def _find_iface_guid(adapter_name: str) -> str | None:
    out = run_quiet(
        f"(Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue).InterfaceGuid"
    )
    return out.strip() if out else None


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class DeepVerifySpoofer(SpoofModule):
    name = "deep_verify"
    description = "Read-only: checks all consumer paths for each identifier."

    def __init__(self, adapter_name: str = "Wi-Fi"):
        self.adapter_name = adapter_name

    def backup(self) -> dict[str, Any]:
        return {"note": "read-only module — nothing to back up"}

    def apply(self, value: Any = None) -> bool:
        self._verify_machine_guid_family()
        self._verify_mac()
        self._verify_hostname()
        self._verify_dhcp_id()
        return True

    def restore(self, backup_data: dict[str, Any]) -> bool:
        log.info("deep_verify is read-only; nothing to restore.")
        return True

    def verify(self) -> str:
        return "see 'apply' output"

    # -----------------------------------------------------------------
    # Verifiers
    # -----------------------------------------------------------------

    def _verify_machine_guid_family(self) -> None:
        """
        These four values are DIFFERENT identifiers, not copies of one.
        We print them together for context but do not compare.
        """
        log.info("=" * 68)
        log.info("MachineGuid family — 4 distinct identifiers (not interchangeable)")
        log.info("=" * 68)
        sources = {
            "MachineGuid (device install ID) [HKLM\\SOFTWARE\\Microsoft\\Cryptography]":
                _reg(winreg.HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, "MachineGuid"),
            "SQMClient MachineId (telemetry ID) [HKLM\\SOFTWARE\\Microsoft\\SQMClient]":
                _reg(winreg.HKEY_LOCAL_MACHINE, SQM_CLIENT_KEY, "MachineId"),
            "OneSettings DeviceId (MS account link) [HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\DeviceAttributes]":
                _reg(winreg.HKEY_LOCAL_MACHINE, ONESETTINGS_KEY, "DeviceId"),
            "SMBIOS UUID via WMI [Win32_ComputerSystemProduct.UUID]":
                _ps("(Get-CimInstance Win32_ComputerSystemProduct).UUID"),
        }
        self._report_sources(sources, compare_values=False)

    def _verify_mac(self) -> None:
        log.info("=" * 68)
        log.info(f"MAC — consumer paths for adapter '{self.adapter_name}'")
        log.info("=" * 68)

        iface_desc = run_quiet(
            f"(Get-NetAdapter -Name '{self.adapter_name}' -ErrorAction SilentlyContinue).InterfaceDescription"
        )
        subkey = _find_mac_subkey(iface_desc) if iface_desc else None

        reg_netaddr = "<unresolved>"
        reg_permaddr = "<unresolved>"
        if subkey:
            reg_netaddr = _reg(
                winreg.HKEY_LOCAL_MACHINE,
                f"{NET_CLASS_KEY}\\{subkey}",
                "NetworkAddress",
            )
            reg_permaddr = _reg(
                winreg.HKEY_LOCAL_MACHINE,
                f"{NET_CLASS_KEY}\\{subkey}",
                "PermanentAddress",
            )

        sources = {
            "Registry NetworkAddress":
                reg_netaddr,
            "Registry PermanentAddress":
                reg_permaddr,
            "Native Get-NetAdapter":
                _ps(f"(Get-NetAdapter -Name '{self.adapter_name}' -ErrorAction SilentlyContinue).MacAddress"),
            "WMI Win32_NetworkAdapter":
                _ps(
                    f"(Get-CimInstance Win32_NetworkAdapter "
                    f"-Filter \"NetConnectionID='{self.adapter_name}'\").MACAddress"
                ),
        }
        self._report_sources(sources, compare_values=True)

    def _verify_hostname(self) -> None:
        log.info("=" * 68)
        log.info("Hostname — consumer paths")
        log.info("=" * 68)
        sources = {
            "Environment $env:COMPUTERNAME":
                _ps("$env:COMPUTERNAME"),
            "Registry ComputerName (pending)":
                _reg(winreg.HKEY_LOCAL_MACHINE, COMPUTERNAME_KEY, "ComputerName"),
            "Registry ActiveComputerName (active)":
                _reg(winreg.HKEY_LOCAL_MACHINE, ACTIVE_COMPUTERNAME_KEY, "ComputerName"),
            "Registry Tcpip\\Hostname":
                _reg(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMETERS, "Hostname"),
            "Registry Tcpip\\NV Hostname":
                _reg(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMETERS, "NV Hostname"),
            "WMI Win32_ComputerSystem.Name":
                _ps("(Get-CimInstance Win32_ComputerSystem).Name"),
        }
        self._report_sources(sources, compare_values=True)

    def _verify_dhcp_id(self) -> None:
        log.info("=" * 68)
        log.info(f"DHCP client identity for adapter '{self.adapter_name}'")
        log.info("=" * 68)
        guid = _find_iface_guid(self.adapter_name)
        if not guid:
            log.warning("Could not resolve interface GUID; skipping DHCP check.")
            return
        sources = {
            "Registry DhcpClientIdentifier":
                _reg(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"{TCPIP_INTERFACES}\\{guid}",
                    "DhcpClientIdentifier",
                ),
            "Registry DhcpNetworkHint":
                _reg(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"{TCPIP_INTERFACES}\\{guid}",
                    "DhcpNetworkHint",
                ),
            "Active IPv4 lease (Get-NetIPAddress)":
                _ps(
                    f"(Get-NetIPAddress -InterfaceAlias '{self.adapter_name}' "
                    f"-AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress"
                ),
        }
        # DhcpClientIdentifier and IPAddress are different kinds of values;
        # compare only makes sense across identifier-shaped sources.
        self._report_sources(sources, compare_values=False)

    # -----------------------------------------------------------------
    # Reporting
    # -----------------------------------------------------------------

    @staticmethod
    def _report_sources(sources: dict[str, str], compare_values: bool = True) -> None:
        """
        Print each source and (optionally) compare normalized values.

        compare_values=True  -> flag disagreement when distinct normalized values > 1
        compare_values=False -> just list values (sources are different identifiers)
        """
        normalized: dict[str, str] = {}
        for src, val in sources.items():
            log.info(f"  {src}")
            log.info(f"      = {val}")
            normalized[src] = _normalize(val)

        if not compare_values:
            log.info("")
            return

        # Filter out sentinel non-values for comparison
        real = {
            v for v in normalized.values()
            if v and not (v.startswith("<") and v.endswith(">"))
        }

        if len(real) <= 1:
            log.info("  => CONSISTENT (all consumer paths report the same value)")
        else:
            log.warning(
                f"  => DISAGREEMENT — {len(real)} distinct value(s) across consumer paths"
            )
        log.info("")