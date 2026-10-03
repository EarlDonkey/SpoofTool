# SpoofTool

A user-mode hardware identifier spoofer for Windows. Spoofs:
- MAC address (per adapter)
- MachineGuid + SQMClient MachineId
- DHCP client identifier
- Computer hostname (+ Tcpip hostname sync)

## Install (dev)

    pip install -r requirements.txt

## Usage

    python main.py --help

Interactive menu (double-clickable after PyInstaller build):

    python spoof_tool_launcher.py

## Build standalone EXE

    pyinstaller --onefile --name SpoofTool --uac-admin --console ^
        --collect-submodules core --collect-submodules modules ^
        spoof_tool_launcher.py

Output: `dist\SpoofTool.exe`

## Architecture

- `core/` — shared utilities (registry, PowerShell, backup, logging, admin)
- `modules/` — one module per spoofable identifier; each implements
  `backup() / apply() / restore() / verify()` and optionally `repair()`
- `main.py` — CLI entry point
- `spoof_tool_launcher.py` — interactive menu for the packaged EXE

## Not yet spoofed

- SMBIOS UUID (`Win32_ComputerSystemProduct.UUID`) — requires kernel driver
- Volume serial number on system drive
- Firmware-level identifiers

## Status

User-mode layer complete. Kernel driver in development.