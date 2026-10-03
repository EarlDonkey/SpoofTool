"""
Backup manager: saves module state to disk, restores on demand.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.logger import log

BACKUP_DIR = Path(__file__).parent.parent / "backups"


class BackupManager:
    def __init__(self, tag: str = "default"):
        BACKUP_DIR.mkdir(exist_ok=True)
        self.tag = tag
        # If the tag already looks like a session tag, don't double-prefix.
        if tag.startswith("session-"):
            self.session_file = BACKUP_DIR / f"{tag}.json"
        else:
            self.session_file = BACKUP_DIR / f"session_{tag}.json"

    def save(self, module_name: str, data: dict[str, Any]) -> None:
        """Merge module backup data into the session file."""
        session = self._load_session()
        session[module_name] = {
            "timestamp": datetime.now().isoformat(),
            "data": data,
        }
        self.session_file.write_text(json.dumps(session, indent=2))
        log.info(f"Backed up '{module_name}' to {self.session_file.name}")

    def load(self, module_name: str) -> dict[str, Any] | None:
        session = self._load_session()
        entry = session.get(module_name)
        return entry["data"] if entry else None

    def _load_session(self) -> dict:
        if not self.session_file.exists():
            return {}
        try:
            return json.loads(self.session_file.read_text())
        except json.JSONDecodeError:
            log.warning(f"Corrupt backup file: {self.session_file}")
            return {}