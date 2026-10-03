"""
PowerShell subprocess wrapper with proper quoting and error handling.
"""
import subprocess
from typing import Optional


def run(script: str, timeout: int = 30, check: bool = False) -> tuple[int, str, str]:
    """
    Run a PowerShell script.

    Returns (returncode, stdout, stderr).
    If check=True, raises RuntimeError on non-zero exit.
    """
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"PowerShell failed (exit {completed.returncode}):\n{completed.stderr}"
        )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def run_quiet(script: str, timeout: int = 30) -> str:
    """Run and return stdout only. Suppresses errors."""
    _, stdout, _ = run(script, timeout=timeout, check=False)
    return stdout