"""
DHCP Client Identifier spoofer.

The DHCP client ID is what Windows sends to a DHCP server when requesting
a lease. By default it's derived from the MAC address. Overriding it means
the DHCP server sees a different device even after a MAC change — or keeps
seeing the same one across MAC changes.

Registry:
  HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{GUID}
  Value: DhcpClientIdentifier (REG_SZ, hex string)

Interface GUID lookup: matches the adapter name via Get-NetAdapter.

Applies: On next DHCP renew. Force with:
  ipconfig /release && ipconfig /renew
"""
from typing import Any

import winreg

from core import registry
from core.logger import log
from core.powershell import run_quiet
from modules.base import SpoofModule

TCPIP_INTERFACES = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
VALUE_NAME = "DhcpClientIdentifier"


class DhcpIdSpoofer(SpoofModule):
    name = "dhcp_id"
    description = "Spoofs the DHCP client identifier for a network adapter."

    def __init__(self, adapter_name: str = "Wi-Fi"):
        self.adapter_name = adapter_name
        self._iface_guid: str | None = None

    # ---- Interface GUID discovery ----

    def _find_interface_guid(self) -> str | None:
        """Map adapter name -> Tcpip interface GUID via PowerShell."""
        out = run_quiet(
            f"(Get-NetAdapter -Name '{self.adapter_name}').InterfaceGuid"
        )
        if out and len(out) >= 38 and out.startswith("{"):
            return out.strip()
        log.warning(f"Could not resolve interface GUID for '{self.adapter_name}'.")
        return None

    def _require_guid(self) -> str:
        if self._iface_guid is None:
            self._iface_guid = self._find_interface_guid()
        if self._iface_guid is None:
            raise RuntimeError(
                f"Interface GUID for '{self.adapter_name}' not found."
            )
        return self._iface_guid

    def _reg_path(self) -> str:
        return f"{TCPIP_INTERFACES}\\{self._require_guid()}"

    # ---- SpoofModule interface ----

    def backup(self) -> dict[str, Any]:
        path = self._reg_path()
        existing = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, path, VALUE_NAME
        )
        return {
            "adapter": self.adapter_name,
            "interface_guid": self._require_guid(),
            "had_dhcp_client_id": existing is not None,
            "original_dhcp_client_id": existing,
        }

    def apply(self, value: Any = None) -> bool:
        path = self._reg_path()

        if value is None:
            # Random hex string, 14 chars (7 bytes) prefixed with type 01 (Ethernet).
            # Format: 01 + 6 random bytes = "01XXXXXXXXXXXX" (14 chars)
            import random
            rand_bytes = "".join(random.choices("0123456789ABCDEF", k=12))
            client_id = f"01{rand_bytes}"
            log.info(f"Generated random DHCP client ID: {client_id}")
        else:
            client_id = str(value).upper()
            if not all(c in "0123456789ABCDEF" for c in client_id):
                raise ValueError(
                    f"DHCP client ID must be hex, got: {client_id}"
                )

        registry.write_value(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            VALUE_NAME,
            client_id,
            winreg.REG_SZ,
        )
        log.info(f"Wrote DhcpClientIdentifier={client_id}")

        self._renew_lease()
        return True

    def restore(self, backup_data: dict[str, Any]) -> bool:
        path = self._reg_path()

        if backup_data["had_dhcp_client_id"]:
            registry.write_value(
                winreg.HKEY_LOCAL_MACHINE,
                path,
                VALUE_NAME,
                backup_data["original_dhcp_client_id"],
                winreg.REG_SZ,
            )
            log.info(
                f"Restored DhcpClientIdentifier="
                f"{backup_data['original_dhcp_client_id']}"
            )
        else:
            deleted = registry.delete_value(
                winreg.HKEY_LOCAL_MACHINE, path, VALUE_NAME
            )
            log.info(
                "Removed DhcpClientIdentifier override (default = derive from MAC)."
                if deleted else
                "No DhcpClientIdentifier was present."
            )

        self._renew_lease()
        return True

    def verify(self) -> str:
        path = self._reg_path()
        val = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, path, VALUE_NAME
        )
        return str(val) if val is not None else "<absent — using MAC-derived ID>"

    # ---- Lease control ----

    def _renew_lease(self) -> None:
        log.info(f"Renewing DHCP lease on '{self.adapter_name}'...")
        run_quiet(f"ipconfig /release '{self.adapter_name}'")
        run_quiet(f"ipconfig /renew '{self.adapter_name}'")