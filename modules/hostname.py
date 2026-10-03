"""
Hostname / computer name spoofer.

Uses Rename-Computer (the supported method) for the pending name and SAM
database entry. Additionally writes the Tcpip\\Parameters Hostname and
NV Hostname registry values directly, so that all consumer paths agree
immediately without requiring a reboot.

Consumer paths covered:
  - HKLM\\SYSTEM\\...\\Control\\ComputerName\\ComputerName            (pending)
  - HKLM\\SYSTEM\\...\\Control\\ComputerName\\ActiveComputerName      (active, reboot-only)
  - HKLM\\SYSTEM\\...\\Services\\Tcpip\\Parameters\\Hostname          (we write)
  - HKLM\\SYSTEM\\...\\Services\\Tcpip\\Parameters\\NV Hostname       (we write)

Note: ActiveComputerName is only updated by the OS on reboot. There is no
supported way to change it from user-mode. Rebooting after apply is still
recommended if you need it to reflect the new name.
"""
import re
from typing import Any

import winreg

from core import registry
from core.logger import log
from core.powershell import run, run_quiet
from modules.base import SpoofModule


COMPUTERNAME_KEY = r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
ACTIVE_COMPUTERNAME_KEY = r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
TCPIP_PARAMETERS = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9-]{1,15}$")


def _validate_hostname(name: str) -> str:
    if not _HOSTNAME_RE.match(name):
        raise ValueError(
            f"Invalid hostname '{name}'. Must be 1-15 chars, "
            "letters/digits/hyphens only."
        )
    if name.isdigit():
        raise ValueError("Hostname cannot be all digits.")
    if name.startswith("-") or name.endswith("-"):
        raise ValueError("Hostname cannot start or end with a hyphen.")
    return name


def _read_pending_hostname() -> str:
    val = registry.read_value(
        winreg.HKEY_LOCAL_MACHINE, COMPUTERNAME_KEY, "ComputerName"
    )
    if val is None:
        raise RuntimeError(
            f"Could not read pending hostname from {COMPUTERNAME_KEY}\\ComputerName"
        )
    return str(val)


def _read_active_hostname() -> str:
    val = registry.read_value(
        winreg.HKEY_LOCAL_MACHINE, ACTIVE_COMPUTERNAME_KEY, "ComputerName"
    )
    if val is None:
        return run_quiet("$env:COMPUTERNAME")
    return str(val)


def _read_tcpip_values() -> dict[str, str | None]:
    """Read the Tcpip hostname values so we can back them up."""
    return {
        "Hostname": registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMETERS, "Hostname"
        ),
        "NV Hostname": registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMETERS, "NV Hostname"
        ),
    }


def _write_tcpip_hostnames(name: str) -> None:
    """Write Hostname and NV Hostname to the Tcpip\\Parameters key."""
    for value_name in ("Hostname", "NV Hostname"):
        try:
            registry.write_value(
                winreg.HKEY_LOCAL_MACHINE,
                TCPIP_PARAMETERS,
                value_name,
                name,
                winreg.REG_SZ,
            )
            log.debug(f"Wrote Tcpip\\Parameters\\{value_name} = {name}")
        except Exception as e:
            log.warning(f"Failed to write {value_name}: {e}")


class HostnameSpoofer(SpoofModule):
    name = "hostname"
    description = "Renames the computer and syncs all consumer paths."

    def backup(self) -> dict[str, Any]:
        pending = _read_pending_hostname()
        active = _read_active_hostname()
        tcpip = _read_tcpip_values()
        log.debug(
            f"pending={pending} active={active} "
            f"tcpip_hostname={tcpip['Hostname']} tcpip_nv={tcpip['NV Hostname']}"
        )
        return {
            "original_hostname": pending,
            "active_hostname": active,
            "tcpip_hostname": tcpip["Hostname"],
            "tcpip_nv_hostname": tcpip["NV Hostname"],
        }

    def apply(self, value: Any = None) -> bool:
        current_pending = _read_pending_hostname()

        if value is None:
            import random
            suffix = "".join(random.choices("0123456789ABCDEF", k=6))
            new_name = f"DESKTOP-{suffix}"
            log.info(f"Generated random hostname: {new_name}")
        else:
            new_name = str(value)
            _validate_hostname(new_name)
            log.info(f"Using custom hostname: {new_name}")

        # Step 1: pending key via Rename-Computer (also updates SAM + services).
        if new_name.upper() != current_pending.upper():
            rc, _, err = run(f"Rename-Computer -NewName '{new_name}' -Force")
            if rc != 0:
                raise RuntimeError(f"Rename-Computer failed: {err}")
            log.info(f"Pending hostname set to '{new_name}'.")
        else:
            log.info(f"Pending hostname is already '{current_pending}'.")

        # Step 2: force-sync the Tcpip values so they don't lag.
        _write_tcpip_hostnames(new_name)
        log.info(f"Tcpip\\Parameters Hostname + NV Hostname set to '{new_name}'.")

        log.info("REBOOT RECOMMENDED for ActiveComputerName and env vars to refresh.")
        return True

    def restore(self, backup_data: dict[str, Any]) -> bool:
        original = backup_data.get("original_hostname")
        if original is None:
            log.error("Backup missing 'original_hostname'. Cannot restore.")
            return False

        active = _read_active_hostname()
        pending = _read_pending_hostname()

        # --- Step 1: restore the primary (ComputerName\ComputerName) ---
        if original.upper() == pending.upper():
            log.info(f"Pending hostname already '{original}'. No rename needed.")
        elif original.upper() == active.upper() and pending.upper() != active.upper():
            log.info(
                f"Reverting pending rename '{pending}' -> '{original}' via registry."
            )
            try:
                registry.write_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    COMPUTERNAME_KEY,
                    "ComputerName",
                    original,
                    winreg.REG_SZ,
                )
            except Exception as e:
                log.error(f"Registry revert failed: {e}")
                return False
        else:
            rc, _, err = run(f"Rename-Computer -NewName '{original}' -Force")
            if rc != 0:
                log.error(f"Rename-Computer (restore) failed: {err}")
                return False
            log.info(f"Pending hostname restored to '{original}'.")

        # --- Step 2: restore Tcpip values (with backward-compat fallback) ---
        # Old backups may not have these keys. If they're absent, we cannot
        # restore precisely — but we can still enforce consistency by
        # syncing them to the restored primary. This is the same operation
        # repair() performs.
        has_tcpip_backup = (
            "tcpip_hostname" in backup_data
            or "tcpip_nv_hostname" in backup_data
        )

        if has_tcpip_backup:
            for value_name, backup_key in (
                ("Hostname", "tcpip_hostname"),
                ("NV Hostname", "tcpip_nv_hostname"),
            ):
                original_val = backup_data.get(backup_key)
                if original_val is None:
                    log.info(
                        f"No backup for Tcpip\\Parameters\\{value_name}; "
                        "will repair instead."
                    )
                    continue
                try:
                    registry.write_value(
                        winreg.HKEY_LOCAL_MACHINE,
                        TCPIP_PARAMETERS,
                        value_name,
                        original_val,
                        winreg.REG_SZ,
                    )
                    log.info(
                        f"Restored Tcpip\\Parameters\\{value_name} = {original_val}"
                    )
                except Exception as e:
                    log.warning(f"Failed to restore {value_name}: {e}")
        else:
            log.info(
                "Backup lacks Tcpip values (pre-upgrade format); "
                "running repair to enforce consistency."
            )

        # Always run repair afterward to handle any missing values or
        # case-mismatched values. It's idempotent — safe to run every time.
        self.repair()

        log.info("REBOOT RECOMMENDED for full restoration of ActiveComputerName.")
        return True
    
    def repair(self) -> bool:
        """
        Sync Tcpip\\Parameters Hostname and NV Hostname to match the pending
        ComputerName. Does NOT change the primary hostname.

        This fixes the common case where a previous spoof left the Tcpip
        values holding a value that no longer matches the primary.
        """
        pending = _read_pending_hostname()
        log.info(f"Pending hostname: {pending}")

        try:
            _write_tcpip_hostnames(pending)
            log.info(
                f"Tcpip\\Parameters Hostname + NV Hostname set to '{pending}' "
                "to match pending ComputerName."
            )
        except Exception as e:
            log.error(f"Repair failed: {e}")
            return False

        log.info("REBOOT RECOMMENDED for ActiveComputerName to refresh.")
        return True

    def verify(self) -> str:
        pending = _read_pending_hostname()
        active = _read_active_hostname()
        tcpip = _read_tcpip_values()
        # Quick sanity: are the Tcpip values in sync?
        mismatches = []
        for k, v in tcpip.items():
            if v and v.upper() != pending.upper():
                mismatches.append(f"{k}={v}")
        suffix = f" [MISMATCH: {', '.join(mismatches)}]" if mismatches else ""
        if pending.upper() != active.upper():
            return f"{pending} (pending; active until reboot: {active}){suffix}"
        return f"{pending}{suffix}"