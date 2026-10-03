"""
Windows registry helpers with backup support.
"""
import winreg
from typing import Any, Optional


def read_value(root: int, path: str, name: str) -> Optional[Any]:
    """Read a registry value. Returns None if not found."""
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except FileNotFoundError:
        return None
    except OSError as e:
        raise RuntimeError(f"Registry read failed for {path}\\{name}: {e}")


def write_value(root: int, path: str, name: str, value: Any, reg_type: int) -> bool:
    """Write a registry value, creating the key if needed."""
    try:
        with winreg.CreateKeyEx(root, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, reg_type, value)
        return True
    except OSError as e:
        raise RuntimeError(f"Registry write failed for {path}\\{name}: {e}")


def delete_value(root: int, path: str, name: str) -> bool:
    """Delete a registry value. Returns False if it didn't exist."""
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
        return True
    except FileNotFoundError:
        return False
    except OSError as e:
        raise RuntimeError(f"Registry delete failed for {path}\\{name}: {e}")


def enum_subkeys(root: int, path: str) -> list[str]:
    """List all subkey names under a registry path."""
    subkeys = []
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    return subkeys