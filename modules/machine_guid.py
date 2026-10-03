"""
MachineGuid family spoofer.

Spoofs two correlated but distinct identifiers:
  - HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid
        Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx  (lowercase, no braces)
        Purpose: device installation ID

  - HKLM\\SOFTWARE\\Microsoft\\SQMClient\\MachineId
        Format: {XXXXXXXX-XXXX-4XXX-YXXX-XXXXXXXXXXXX}  (uppercase, braces)
        Purpose: telemetry correlation ID

These are INDEPENDENT on real Windows systems. We generate two different
random GUIDs (never the same value) to avoid creating a detectable pattern.

Also supports `repair` — if SQMClient MachineId is missing but MachineGuid
exists, generates a plausible value. Does NOT touch MachineGuid.

OneSettings DeviceAttributes\\DeviceId is left untouched (usually absent;
setting it may trigger unwanted telemetry re-sync).
"""
import re
import uuid
from typing import Any

import winreg

from core import registry
from core.logger import log
from core.powershell import run
from modules.base import SpoofModule


MACHINE_GUID_KEY = r"SOFTWARE\Microsoft\Cryptography"
MACHINE_GUID_VALUE = "MachineGuid"

SQM_CLIENT_KEY = r"SOFTWARE\Microsoft\SQMClient"
SQM_CLIENT_VALUE = "MachineId"

_BARE_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_BRACED_GUID_RE = re.compile(
    r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$"
)


def _new_machine_guid() -> str:
    """Generate a lowercase, brace-less UUIDv4."""
    return str(uuid.uuid4()).lower()


def _new_sqm_machine_id() -> str:
    """Generate an UPPERCASE, braced UUIDv4 (SQM format)."""
    return "{" + str(uuid.uuid4()).upper() + "}"


def _validate_machine_guid(value: str) -> str:
    v = str(value).strip().lower()
    if not _BARE_GUID_RE.match(v):
        raise ValueError(
            f"Invalid MachineGuid format: {value!r}. Expected lowercase, brace-less UUID."
        )
    return v


def _validate_sqm_machine_id(value: str) -> str:
    v = str(value).strip().upper()
    if not v.startswith("{"):
        v = "{" + v.lstrip("{").rstrip("}") + "}"
    if not _BRACED_GUID_RE.match(v):
        raise ValueError(
            f"Invalid SQMClient MachineId format: {value!r}. "
            "Expected {UPPERCASE-GUID}."
        )
    return v


class MachineGuidSpoofer(SpoofModule):
    name = "machine_guid"
    description = (
        "Spoofs MachineGuid and its telemetry counterpart SQMClient\\MachineId."
    )

    # ------------------------------------------------------------------
    # backup / apply / restore / verify / repair
    # ------------------------------------------------------------------

    def backup(self) -> dict[str, Any]:
        machine_guid = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, MACHINE_GUID_VALUE
        )
        if machine_guid is None:
            raise RuntimeError(
                f"{MACHINE_GUID_KEY}\\{MACHINE_GUID_VALUE} not found."
            )

        sqm_id = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, SQM_CLIENT_KEY, SQM_CLIENT_VALUE
        )

        log.debug(
            f"Backup: MachineGuid={machine_guid}, SQMClient MachineId={sqm_id}"
        )
        return {
            "original_machine_guid": str(machine_guid),
            "had_sqm_machine_id": sqm_id is not None,
            "original_sqm_machine_id": str(sqm_id) if sqm_id is not None else None,
        }

    def apply(self, value: Any = None) -> bool:
        if value is None:
            new_machine_guid = _new_machine_guid()
            new_sqm_id = _new_sqm_machine_id()
            log.info(f"Generated MachineGuid:       {new_machine_guid}")
            log.info(f"Generated SQMClient MachineId: {new_sqm_id}")
        else:
            new_machine_guid = _validate_machine_guid(value)
            # SQMClient is always a separate random — never equal to MachineGuid.
            new_sqm_id = _new_sqm_machine_id()
            log.info(f"Using provided MachineGuid:    {new_machine_guid}")
            log.info(f"Generated matching SQMClient:  {new_sqm_id}")

        # Sanity: they must not be equal (even modulo braces/case).
        if new_machine_guid.upper() == new_sqm_id.strip("{}").upper():
            raise RuntimeError(
                "Internal error: MachineGuid and SQMClient MachineId would be equal."
            )

        # Write MachineGuid
        registry.write_value(
            winreg.HKEY_LOCAL_MACHINE,
            MACHINE_GUID_KEY,
            MACHINE_GUID_VALUE,
            new_machine_guid,
            winreg.REG_SZ,
        )
        log.info(f"Wrote MachineGuid={new_machine_guid}")

        # Write SQMClient MachineId
        registry.write_value(
            winreg.HKEY_LOCAL_MACHINE,
            SQM_CLIENT_KEY,
            SQM_CLIENT_VALUE,
            new_sqm_id,
            winreg.REG_SZ,
        )
        log.info(f"Wrote SQMClient MachineId={new_sqm_id}")

        self._restart_cryptsvc()
        return True

    def restore(self, backup_data: dict[str, Any]) -> bool:
        # Backward compatibility: old backups only had 'original_machine_guid'.
        # If SQMClient fields are absent, treat as "was present, but we don't
        # know the original" — set a plausible value via repair to keep the
        # system consistent.
        original_machine_guid = backup_data.get("original_machine_guid")
        if original_machine_guid is None:
            log.error("Backup missing 'original_machine_guid'. Cannot restore.")
            return False

        registry.write_value(
            winreg.HKEY_LOCAL_MACHINE,
            MACHINE_GUID_KEY,
            MACHINE_GUID_VALUE,
            original_machine_guid,
            winreg.REG_SZ,
        )
        log.info(f"Restored MachineGuid={original_machine_guid}")

        # Handle SQMClient restore with backward compatibility.
        if "had_sqm_machine_id" in backup_data:
            if backup_data["had_sqm_machine_id"]:
                original_sqm = backup_data.get("original_sqm_machine_id")
                if original_sqm is None:
                    log.warning(
                        "Backup says SQMClient existed but original value is "
                        "missing; generating a fresh one via repair."
                    )
                    self.repair()
                else:
                    registry.write_value(
                        winreg.HKEY_LOCAL_MACHINE,
                        SQM_CLIENT_KEY,
                        SQM_CLIENT_VALUE,
                        original_sqm,
                        winreg.REG_SZ,
                    )
                    log.info(f"Restored SQMClient MachineId={original_sqm}")
            else:
                deleted = registry.delete_value(
                    winreg.HKEY_LOCAL_MACHINE, SQM_CLIENT_KEY, SQM_CLIENT_VALUE
                )
                if deleted:
                    log.info("Removed SQMClient MachineId (was absent at backup).")
                else:
                    log.info("SQMClient MachineId was already absent.")
        else:
            # Very old backup: no SQMClient info at all. Use repair to ensure
            # SQMClient is present and consistent with the restored MachineGuid.
            log.info(
                "Backup lacks SQMClient info (pre-upgrade format); "
                "running repair to ensure consistency."
            )
            self.repair()

        self._restart_cryptsvc()
        return True

    def verify(self) -> str:
        mg = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, MACHINE_GUID_VALUE
        )
        sqm = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, SQM_CLIENT_KEY, SQM_CLIENT_VALUE
        )
        return (
            f"MachineGuid={mg if mg else '<absent>'} | "
            f"SQMClient={sqm if sqm else '<absent>'}"
        )

    def repair(self) -> bool:
        """
        Ensure SQMClient MachineId exists and is not equal to MachineGuid.

        Does NOT change MachineGuid. Only adds/fixes SQMClient when it is
        missing or (rarely) equal to MachineGuid.
        """
        mg = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, MACHINE_GUID_KEY, MACHINE_GUID_VALUE
        )
        if mg is None:
            log.error(
                "Cannot repair: MachineGuid is missing. "
                "Run 'apply machine_guid' first."
            )
            return False

        mg_norm = str(mg).strip().lower()

        sqm = registry.read_value(
            winreg.HKEY_LOCAL_MACHINE, SQM_CLIENT_KEY, SQM_CLIENT_VALUE
        )

        # Case 1: SQMClient missing
        if sqm is None:
            new_sqm = _new_sqm_machine_id()
            registry.write_value(
                winreg.HKEY_LOCAL_MACHINE,
                SQM_CLIENT_KEY,
                SQM_CLIENT_VALUE,
                new_sqm,
                winreg.REG_SZ,
            )
            log.info(f"SQMClient MachineId was missing — created {new_sqm}")
            self._restart_cryptsvc()
            return True

        # Case 2: SQMClient equals MachineGuid (detectable pattern)
        if str(sqm).strip("{}").lower() == mg_norm:
            new_sqm = _new_sqm_machine_id()
            registry.write_value(
                winreg.HKEY_LOCAL_MACHINE,
                SQM_CLIENT_KEY,
                SQM_CLIENT_VALUE,
                new_sqm,
                winreg.REG_SZ,
            )
            log.info(
                f"SQMClient MachineId was equal to MachineGuid (detectable pattern); "
                f"replaced with {new_sqm}"
            )
            self._restart_cryptsvc()
            return True

        # Case 3: SQMClient is present and different — nothing to do.
        log.info(
            f"SQMClient MachineId is present and distinct from MachineGuid. "
            "No repair needed."
        )
        return True

    # ------------------------------------------------------------------
    # Service control
    # ------------------------------------------------------------------

    @staticmethod
    def _restart_cryptsvc() -> None:
        rc, _, err = run("Restart-Service CryptSvc -Force")
        if rc != 0:
            log.debug(f"CryptSvc restart failed (non-fatal): {err}")
        else:
            log.debug("CryptSvc restarted.")