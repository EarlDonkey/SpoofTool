"""
Admin privilege detection and auto-elevation.
"""
import ctypes
import sys
import os


def is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin(auto_elevate: bool = True) -> bool:
    """
    Ensure the process runs as admin.

    Returns True if already admin.
    If not admin and auto_elevate=True, relaunches the process elevated
    and exits the current process. If auto_elevate=False, returns False.
    """
    if is_admin():
        return True

    if not auto_elevate:
        return False

    print("[!] Administrator privileges required. Requesting elevation...")
    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{a}"' for a in sys.argv[1:]])

    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        if ret <= 32:
            print("[-] Elevation failed or was cancelled.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Elevation error: {e}")
        sys.exit(1)

    # The elevated instance is now running; exit this one.
    sys.exit(0)