"""
Entry point for the packaged EXE.

When run with args:    forwards to main.py's CLI
When run without args: shows an interactive menu
"""
import sys
import os


def _run_interactive_menu() -> int:
    """Simple text menu shown when the user double-clicks the EXE."""
    from core.admin import require_admin
    from modules.session import SessionOrchestrator

    require_admin(auto_elevate=True)

    while True:
        print()
        print("=" * 60)
        print("  SpoofTool — Hardware Identifier Spoofer")
        print("=" * 60)
        print()
        print("  1. Apply full spoof (all modules)")
        print("  2. Restore last session")
        print("  3. Verify current state (deep verify)")
        print("  4. Reset to factory defaults")
        print("  5. Advanced (open terminal for full CLI)")
        print("  6. Exit")
        print()

        choice = input("Select [1-6]: ").strip()

        if choice == "1":
            adapter = input("Adapter name [Wi-Fi]: ").strip() or "Wi-Fi"
            orch = SessionOrchestrator(adapter_name=adapter, action="apply")
            orch.apply_all()
            print()
            print(f"Session tag: {orch.tag}")
            print(f"Restore later with: python main.py session restore --tag {orch.tag}")

        elif choice == "2":
            orch = SessionOrchestrator(action="restore")
            print(f"Restoring most recent session: {orch.tag}")
            orch.restore_all()

        elif choice == "3":
            adapter = input("Adapter name [Wi-Fi]: ").strip() or "Wi-Fi"
            from modules.deep_verify import DeepVerifySpoofer
            DeepVerifySpoofer(adapter_name=adapter).apply(None)

        elif choice == "4":
            confirm = input("Reset ALL spoofs to factory? [y/N]: ").strip().lower()
            if confirm == "y":
                # Inline the reset logic (same as cmd_reset)
                from main import cmd_reset
                import argparse
                ns = argparse.Namespace(adapter="Wi-Fi", tag="default")
                cmd_reset(ns)

        elif choice == "5":
            print("Open a terminal in this folder and run:")
            print("  python main.py --help")
            input("Press Enter to return to menu...")

        elif choice == "6":
            return 0
        else:
            print("Invalid choice.")


def main() -> int:
    if len(sys.argv) > 1:
        # Args provided — delegate to normal CLI
        from main import main as cli_main
        return cli_main()
    else:
        # No args — interactive menu
        return _run_interactive_menu()


if __name__ == "__main__":
    sys.exit(main())