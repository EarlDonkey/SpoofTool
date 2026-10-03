"""
MAC address spoofing via the NetworkAddress registry value.

Adapter resolution strategy:
  1. Try to resolve the user-provided name to an InterfaceDescription via
     Get-NetAdapter (this matches what the user sees in PowerShell).
  2. Match that InterfaceDescription against the registry's DriverDesc.
  3. If PowerShell can't find it (virtual/kernel adapters), fall back to
     matching DriverDesc directly with exact -> word -> substring tiers.

This handles both styles of input:
  --adapter "Wi-Fi"                    (matches Get-NetAdapter Name)
  --adapter "MediaTek Wi-Fi 6 MT7921"  (matches DriverDesc substring)
"""
import random
import re
from typing import Any

import winreg

from core import registry
from core.logger import log
from core.powershell import run_quiet
from modules.base import SpoofModule

NET_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"


# ---------------------------------------------------------------------------
# MAC format helpers
# ---------------------------------------------------------------------------

def _clean_mac(mac: str) -> str:
    cleaned = re.sub(r"[^A-Fa-f0-9]", "", mac).upper()
    if len(cleaned) != 12:
        raise ValueError(
            f"MAC must contain exactly 12 hex digits, got {len(cleaned)}."
        )
    first_byte = int(cleaned[0:2], 16)
    if first_byte & 0x01:
        raise ValueError(
            "Multicast bit must be 0. Second hex char must be 0, 2, 4, 6, 8, A, C, or E."
        )
    return cleaned


def _format_mac(raw: str) -> str:
    return "-".join(raw[i:i + 2] for i in range(0, 12, 2))


def _generate_random_mac() -> str:
    first_char = random.choice("0123456789ABCDEF")
    second_char = random.choice("26AE")
    rest = "".join(random.choices("0123456789ABCDEF", k=10))
    return f"{first_char}{second_char}{rest}"


# ---------------------------------------------------------------------------
# Adapter resolution helpers
# ---------------------------------------------------------------------------

def _resolve_interface_description_from_name(name: str) -> str | None:
    """
    Ask PowerShell: what is the InterfaceDescription for the adapter whose
    Get-NetAdapter Name is `name`?

    Returns None if no NetAdapter has that Name.
    """
    out = run_quiet(
        f"(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue).InterfaceDescription"
    )
    return out or None


def _enumerate_registry_adapters() -> list[tuple[str, str]]:
    """Return list of (subkey, DriverDesc) for all numeric adapter subkeys."""
    result: list[tuple[str, str]] = []
    for subkey_name in registry.enum_subkeys(winreg.HKEY_LOCAL_MACHINE, NET_CLASS_KEY):
        if not subkey_name.isdigit():
            continue
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                f"{NET_CLASS_KEY}\\{subkey_name}",
                0,
                winreg.KEY_READ,
            ) as subkey:
                desc, _ = winreg.QueryValueEx(subkey, "DriverDesc")
            result.append((subkey_name, desc))
        except FileNotFoundError:
            continue
        except OSError as e:
            log.warning(f"Registry read error on {subkey_name}: {e}")
    return result


def _find_subkey_by_description(target: str) -> str | None:
    """
    Match `target` against registry DriverDesc values.

    Tiers:
      1. Exact (case-insensitive) match. Must be unique.
      2. Whole-word match. Must be unique.
      3. Substring match. Must be unique.

    Raises RuntimeError if any tier has >1 match.
    Returns None if no tier matched anything.
    """
    adapters = _enumerate_registry_adapters()
    target_lower = target.lower()
    word_re = re.compile(rf"\b{re.escape(target)}\b", re.IGNORECASE)

    exact:    list[tuple[str, str]] = []
    word:     list[tuple[str, str]] = []
    partial:  list[tuple[str, str]] = []

    for subkey, desc in adapters:
        dl = desc.lower()
        if dl == target_lower:
            exact.append((subkey, desc))
        elif word_re.search(desc):
            word.append((subkey, desc))
        elif target_lower in dl:
            partial.append((subkey, desc))

    for tier_name, tier in (("exact", exact), ("word", word), ("substring", partial)):
        if len(tier) == 1:
            subkey, desc = tier[0]
            log.debug(f"{tier_name} match '{target}' -> {subkey} ({desc})")
            return subkey
        if len(tier) > 1:
            options = "\n".join(f"  {k}: {d}" for k, d in tier)
            raise RuntimeError(
                f"Multiple adapters {tier_name}-match '{target}':\n{options}\n"
                "Be more specific."
            )

    return None


# ---------------------------------------------------------------------------
# SpoofModule implementation
# ---------------------------------------------------------------------------

class MacSpoofer(SpoofModule):
    name = "mac"
    description = "Spoofs the MAC address of a network adapter."

    def __init__(self, adapter_name: str = "Wi-Fi"):
        self.adapter_name = adapter_name
        self._subkey: str | None = None
        self._resolved_net_name: str | None = None

    # ---- Resolution ----

    def _find_subkey(self) -> str | None:
        # Step 1: try to resolve the user's name to an InterfaceDescription
        # via Get-NetAdapter. This is the "user sees this name" path.
        iface_desc = _resolve_interface_description_from_name(self.adapter_name)
        if iface_desc:
            log.debug(
                f"Get-NetAdapter Name '{self.adapter_name}' -> "
                f"InterfaceDescription '{iface_desc}'"
            )
            # Now find the registry subkey whose DriverDesc == iface_desc.
            try:
                return _find_subkey_by_description(iface_desc)
            except RuntimeError:
                # Multiple registry entries share this DriverDesc — that
                # happens for Wi-Fi Direct duplicates. Fall through and
                # let the direct match try to disambiguate.
                log.warning(
                    f"Ambiguous registry match for InterfaceDescription "
                    f"'{iface_desc}', falling back to name-based match."
                )

        # Step 2: fall back — try matching the user's string directly
        # against DriverDesc values.
        return _find_subkey_by_description(self.adapter_name)

    def _require_subkey(self) -> str:
        if self._subkey is None:
            self._subkey = self._find_subkey()
        if self._subkey is None:
            raise RuntimeError(
                f"Adapter '{self.adapter_name}' not found in registry."
            )
        return self._subkey

    def _resolve_netadapter_name(self) -> str | None:
        """
        Return the Get-NetAdapter Name for our adapter, resolved via
        InterfaceDescription (which matches the registry DriverDesc).
        Falls back to using adapter_name directly if it's already a NetAdapter Name.
        """
        # Direct hit: user typed a valid Get-NetAdapter Name.
        out = run_quiet(
            f"(Get-NetAdapter -Name '{self.adapter_name}' "
            f"-ErrorAction SilentlyContinue).Name"
        )
        if out:
            return out

        # Otherwise, resolve via the registry subkey's DriverDesc.
        subkey = self._require_subkey()
        for sk, desc in _enumerate_registry_adapters():
            if sk == subkey:
                out = run_quiet(
                    f"(Get-NetAdapter | Where-Object {{ $_.InterfaceDescription -eq '{desc}' }} "
                    f"| Select-Object -First 1).Name"
                )
                return out or None
        return None

    # ---- Adapter control ----

    def _restart_adapter(self) -> None:
        net_name = self._resolve_netadapter_name()
        if not net_name:
            log.warning(
                f"Adapter '{self.adapter_name}' is not visible to "
                "Get-NetAdapter — cannot restart it. Registry change will "
                "apply on next system reboot."
            )
            return
        log.info(f"Restarting adapter '{net_name}'...")
        run_quiet(f"Disable-NetAdapter -Name '{net_name}' -Confirm:$false")
        run_quiet(f"Enable-NetAdapter -Name '{net_name}' -Confirm:$false")

    # ---- SpoofModule interface ----

    def backup(self) -> dict[str, Any]:
        subkey = self._require_subkey()
        path = f"{NET_CLASS_KEY}\\{subkey}"
        existing = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, path, "NetworkAddress"
        )
        return {
            "adapter": self.adapter_name,
            "subkey": subkey,
            "had_network_address": existing is not None,
            "original_network_address": existing,
        }

    def apply(self, value: Any = None) -> bool:
        subkey = self._require_subkey()
        path = f"{NET_CLASS_KEY}\\{subkey}"

        if value is None:
            raw = _generate_random_mac()
            log.info(f"Generated random MAC: {_format_mac(raw)}")
        else:
            raw = _clean_mac(str(value))

        registry.write_value(
            winreg.HKEY_LOCAL_MACHINE, path, "NetworkAddress", raw, winreg.REG_SZ
        )
        log.info(f"Wrote NetworkAddress={_format_mac(raw)} to subkey {subkey}")

        self._restart_adapter()
        return True

    def restore(self, backup_data: dict[str, Any]) -> bool:
        subkey = backup_data["subkey"]
        path = f"{NET_CLASS_KEY}\\{subkey}"

        if backup_data["had_network_address"]:
            original = backup_data["original_network_address"]
            registry.write_value(
                winreg.HKEY_LOCAL_MACHINE, path, "NetworkAddress", original, winreg.REG_SZ
            )
            log.info(f"Restored original NetworkAddress={original}")
        else:
            deleted = registry.delete_value(
                winreg.HKEY_LOCAL_MACHINE, path, "NetworkAddress"
            )
            if deleted:
                log.info("Removed NetworkAddress override (factory MAC restored).")
            else:
                log.info("No NetworkAddress override was present.")

        self._restart_adapter()
        return True

    def verify(self) -> str:
        """
        Return the currently-visible MAC.

        Matches by Get-NetAdapter Name first (user-facing), then by
        InterfaceDescription (registry-facing), then gives up with a
        clear sentinel.
        """
        # Direct name match
        out = run_quiet(
            f"(Get-NetAdapter -Name '{self.adapter_name}' "
            f"-ErrorAction SilentlyContinue).MacAddress"
        )
        if out:
            return out

        # InterfaceDescription match — resolve via registry subkey
        try:
            subkey = self._require_subkey()
        except RuntimeError:
            return "<adapter not visible to Get-NetAdapter>"

        for sk, desc in _enumerate_registry_adapters():
            if sk == subkey:
                out = run_quiet(
                    f"(Get-NetAdapter | Where-Object {{ $_.InterfaceDescription -eq '{desc}' }} "
                    f"| Select-Object -First 1).MacAddress"
                )
                if out:
                    return out
        return "<adapter not visible to Get-NetAdapter>"