"""
Base interface for all spoof modules.

Every module must implement:
- name: short identifier
- description: what it spoofs
- backup(): save current state
- apply(): change the value
- restore(): revert to backup
- verify(): confirm the change took effect
- repair(): (optional) enforce consistency among derived values without
            changing the primary. Default no-op.
"""
from abc import ABC, abstractmethod
from typing import Any


class SpoofModule(ABC):
    name: str = "unnamed"
    description: str = ""

    @abstractmethod
    def backup(self) -> dict[str, Any]:
        """Capture current state. Return a serializable dict."""
        ...

    @abstractmethod
    def apply(self, value: Any = None) -> bool:
        """Apply the spoof. Return True on success."""
        ...

    @abstractmethod
    def restore(self, backup_data: dict[str, Any]) -> bool:
        """Restore from backup. Return True on success."""
        ...

    @abstractmethod
    def verify(self) -> Any:
        """Return the currently-visible value."""
        ...

    def repair(self) -> bool:
        """
        Enforce consistency among derived values without changing the
        primary identifier. Optional — default no-op.

        Return True if the module is (or was made) consistent.
        """
        return True