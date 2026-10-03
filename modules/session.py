"""
Session orchestrator.

Applies multiple spoof modules in dependency order with a single backup tag.
Reverses cleanly. Runs deep_verify at the end to confirm consumer paths agree.

Semantics:
  - `session apply` backs up the CURRENT state under a new tag, then spoofs.
  - `session restore --tag X` reverts to the state captured at the start of
    session X. This is NOT factory-reset — if you ran session X while already
    spoofed, restoring returns you to that prior spoofed state.
  - For a true factory reset, use `python main.py reset`, which restores from
    the very first backup under tag "default".
"""
from datetime import datetime
from typing import Any

from core.backup import BackupManager
from core.logger import log
from modules.base import SpoofModule
from modules.dhcp_id import DhcpIdSpoofer
from modules.deep_verify import DeepVerifySpoofer
from modules.hostname import HostnameSpoofer
from modules.machine_guid import MachineGuidSpoofer
from modules.mac import MacSpoofer


# Order matters. Documented reasons in the module docstring.
APPLY_ORDER = ["machine_guid", "mac", "dhcp_id", "hostname"]
RESTORE_ORDER = list(reversed(APPLY_ORDER))


class SessionOrchestrator:
    def __init__(
        self,
        adapter_name: str = "Wi-Fi",
        tag: str | None = None,
        *,
        action: str = "restore",
    ):
        """
        action:
          "apply"   -> require an explicit tag, or generate a fresh one
          "restore" / "verify" -> auto-resolve to the most recent session if tag omitted
          "backup"  -> generate fresh tag if none given
        """
        self.adapter_name = adapter_name
        self.action = action

        if tag:
            self.tag = tag
        elif action in ("apply", "backup"):
            from datetime import datetime
            self.tag = f"session-{datetime.now():%Y-%m-%d-%H%M%S}"
        else:
            self.tag = self._resolve_latest_tag()

        self.bm = BackupManager(tag=self.tag)

    @staticmethod
    def _resolve_latest_tag() -> str:
        """Return the most recent session tag, or a fresh one if none exist."""
        from core.backup import BACKUP_DIR
        from datetime import datetime

        candidates = sorted(
            BACKUP_DIR.glob("session-*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        # Filter out non-session tags like session_default.json
        session_tags = [
            p.stem for p in candidates
            if p.stem.startswith("session-")
            and p.stem != "session_default"
            and p.stem.count("-") >= 4  # session-YYYY-MM-DD-HHMMSS
        ]
        if session_tags:
            return session_tags[0]
        return f"session-{datetime.now():%Y-%m-%d-%H%M%S}"

    @staticmethod
    def list_sessions() -> list[str]:
        """Return all session tags, newest first."""
        from core.backup import BACKUP_DIR
        candidates = sorted(
            BACKUP_DIR.glob("session-*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return [
            p.stem for p in candidates
            if p.stem.startswith("session-")
            and p.stem != "session_default"
            and p.stem.count("-") >= 4
        ]

    # ------------------------------------------------------------------
    # Module instantiation
    # ------------------------------------------------------------------

    def _instantiate(self, name: str) -> SpoofModule:
        if name == "machine_guid":
            return MachineGuidSpoofer()
        if name == "mac":
            return MacSpoofer(self.adapter_name)
        if name == "dhcp_id":
            return DhcpIdSpoofer(self.adapter_name)
        if name == "hostname":
            return HostnameSpoofer()
        if name == "deep_verify":
            return DeepVerifySpoofer(self.adapter_name)
        raise ValueError(f"Unknown module: {name}")

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def backup_all(self) -> bool:
        log.info(f"=== Backing up all modules to tag '{self.tag}' ===")
        ok = True
        for name in APPLY_ORDER:
            try:
                mod = self._instantiate(name)
                data = mod.backup()
                self.bm.save(name, data)
            except Exception as e:
                log.error(f"backup {name} failed: {e}")
                ok = False
        if ok:
            log.info(f"Backup complete. Restore with: "
                     f"python main.py session restore --tag {self.tag}")
        return ok

    def apply_all(self) -> bool:
        log.info(f"=== Applying session '{self.tag}' ===")

        # Backup first if not already backed up under this tag.
        existing = {name: self.bm.load(name) for name in APPLY_ORDER}
        if not all(existing.values()):
            log.info("Some modules are not backed up under this tag — backing up now.")
            if not self.backup_all():
                log.error("Backup failed; aborting apply.")
                return False

        for name in APPLY_ORDER:
            try:
                log.info(f"--- {name} ---")
                mod = self._instantiate(name)
                mod.apply(None)
                log.info(f"{name}: {mod.verify()}")
            except Exception as e:
                log.error(f"{name} failed: {e}")
                log.error(
                    f"Apply aborted at '{name}'. Previous modules are still "
                    f"spoofed. To revert: python main.py session restore --tag {self.tag}"
                )
                return False

        log.info("=" * 60)
        log.info("Post-apply verification (all consumer paths)")
        log.info("=" * 60)
        try:
            self._instantiate("deep_verify").apply(None)
        except Exception as e:
            log.error(f"deep_verify failed: {e}")

        log.info("=" * 60)
        log.info("Session applied. REBOOT RECOMMENDED for hostname changes to")
        log.info("propagate to ActiveComputerName, $env:COMPUTERNAME, and WMI.")
        log.info("=" * 60)
        return True

    def restore_all(self) -> bool:
        log.info(f"=== Restoring session '{self.tag}' ===")
        ok = True

        # Reverse order so hostname (last to change) is first to revert.
        for name in RESTORE_ORDER:
            data = self.bm.load(name)
            if data is None:
                log.warning(f"No backup for {name} under tag '{self.tag}'. Skipping.")
                continue
            try:
                log.info(f"--- {name} ---")
                mod = self._instantiate(name)
                mod.restore(data)
                log.info(f"{name}: {mod.verify()}")
            except Exception as e:
                log.error(f"{name} restore failed: {e}")
                ok = False

        log.info("=" * 60)
        log.info("Post-restore verification")
        log.info("=" * 60)
        try:
            self._instantiate("deep_verify").apply(None)
        except Exception as e:
            log.error(f"deep_verify failed: {e}")

        if ok:
            log.info(f"Session '{self.tag}' restored.")
        else:
            log.warning(f"Session '{self.tag}' restored with errors — see above.")
        return ok

    def verify_all(self) -> None:
        log.info(f"=== Verifying session '{self.tag}' ===")
        for name in APPLY_ORDER:
            try:
                mod = self._instantiate(name)
                log.info(f"{name}: {mod.verify()}")
            except Exception as e:
                log.error(f"{name} verify failed: {e}")