"""
Volume serial number spoofer.

Changes the 4-byte NTFS volume serial number stored in the volume boot
record (VBR). Uses Sysinternals volumeid.exe.

DANGER:
  Changing the volume ID of the system drive can break boot, activation,
  and BitLocker. This module refuses to touch the system drive unless
  --force is passed to apply().

Requires volumeid.exe on PATH. Download from:
  https://learn.microsoft.com/en-us/sysinternals/downloads/volumeid

Applies: Immediately for the raw VBR, but some components cache it.
         Windows Explorer cache is cleared on reboot.
"""
import re
import shutil
from typing import Any

from core.logger import log
from core.powershell import run, run_quiet
from modules.base import SpoofModule


def _is_system_drive(drive_letter: str) -> bool:
    """Return True if drive_letter is the system drive (where Windows lives)."""
    sysdrive = run_quiet("$env:SystemDrive").rstrip(":")
    return drive_letter.upper().rstrip(":") == sysdrive.upper()


def _normalize_drive(drive: str) -> str:
    """'C:', 'c', 'C' → 'C'."""
    d = drive.strip().rstrip(":").upper()
    if len(d) != 1 or not d.isalpha():
        raise ValueError(f"Invalid drive letter: {drive}")
    return d


def _find_volumeid() -> str | None:
    """Locate volumeid.exe on PATH."""
    return shutil.which("volumeid") or shutil.which("volumeid.exe")


class VolumeIdSpoofer(SpoofModule):
    name = "volume_id"
    description = "Spoofs NTFS volume serial number (DANGEROUS on system drive)."

    def __init__(self, drive: str = "D"):
        self.drive = _normalize_drive(drive)

    def backup(self) -> dict[str, Any]:
        # Read current volume serial via PowerShell
        out = run_quiet(
            f"(Get-Volume -DriveLetter {self.drive}).SerialNumber"
        )
        if not out:
            raise RuntimeError(f"Could not read serial for drive {self.drive}:")
        # Get-Volume returns something like "1A2B3C4D" (no hyphen)
        log.debug(f"Current volume serial on {self.drive}: {out}")
        return {"drive": self.drive, "original_serial": out.strip()}

    def apply(self, value: Any = None, force: bool = False) -> bool:
        if _is_system_drive(self.drive) and not force:
            raise RuntimeError(
                f"Refusing to modify system drive {self.drive}: without --force. "
                "This can break boot and activation."
            )

        volumeid = _find_volumeid()
        if not volumeid:
            raise RuntimeError(
                "volumeid.exe not found on PATH. "
                "Download from https://learn.microsoft.com/en-us/sysinternals/downloads/volumeid"
            )

        if value is None:
            import random
            # Generate XXXX-XXXX
            a = "".join(random.choices("0123456789ABCDEF", k=4))
            b = "".join(random.choices("0123456789ABCDEF", k=4))
            new_serial = f"{a}-{b}"
            log.info(f"Generated random volume serial: {new_serial}")
        else:
            new_serial = str(value).strip()
            if not re.match(r"^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$", new_serial):
                raise ValueError(
                    f"Volume serial must be XXXX-XXXX, got: {new_serial}"
                )

        rc, _, err = run(f'"{volumeid}" {self.drive}: {new_serial}')
        if rc != 0:
            raise RuntimeError(f"volumeid failed: {err}")
        log.info(f"Volume serial on {self.drive}: set to {new_serial}")
        return True

    def restore(self, backup_data: dict[str, Any]) -> bool:
        volumeid = _find_volumeid()
        if not volumeid:
            raise RuntimeError("volumeid.exe not found on PATH.")

        original = backup_data["original_serial"]
        # Get-Volume returns no hyphen; volumeid accepts XXXX-XXXX
        if len(original) == 8:
            formatted = f"{original[:4]}-{original[4:]}"
        else:
            formatted = original

        drive = backup_data["drive"]
        rc, _, err = run(f'"{volumeid}" {drive}: {formatted}')
        if rc != 0:
            log.error(f"volumeid (restore) failed: {err}")
            return False
        log.info(f"Volume serial on {drive}: restored to {formatted}")
        return True

    def verify(self) -> str:
        out = run_quiet(
            f"(Get-Volume -DriveLetter {self.drive}).SerialNumber"
        )
        if not out:
            return "<unable to read>"
        s = out.strip()
        if len(s) == 8:
            return f"{s[:4]}-{s[4:]}"
        return s