"""
Entry point for the spoof tool.
"""
import argparse
import logging
import sys

from core.admin import require_admin
from core.backup import BackupManager
from core.logger import log
from modules.base import SpoofModule

from modules.mac import MacSpoofer
from modules.session import SessionOrchestrator
from modules.deep_verify import DeepVerifySpoofer
from modules.machine_guid import MachineGuidSpoofer
from modules.dhcp_id import DhcpIdSpoofer
from modules.hostname import HostnameSpoofer
from modules.volume_id import VolumeIdSpoofer


MODULES = {
    "mac":          MacSpoofer,
    "machine_guid": MachineGuidSpoofer,
    "dhcp_id":      DhcpIdSpoofer,
    "deep_verify": DeepVerifySpoofer,
    "hostname":     HostnameSpoofer,
    "volume_id":    VolumeIdSpoofer,
}

ADAPTER_MODULES = {"mac", "dhcp_id", "deep_verify"}
DRIVE_MODULES   = {"volume_id"}

def _build_module(name: str, args) -> SpoofModule:
    cls = MODULES.get(name)
    if cls is None:
        raise ValueError(f"Unknown module: {name}")
    if name in ADAPTER_MODULES:
        return cls(adapter_name=args.adapter)
    if name in DRIVE_MODULES:
        return cls(drive=args.drive)
    return cls()

def cmd_session(args) -> int:
    tag = args.tag if args.tag != "default" else None
    orch = SessionOrchestrator(
        adapter_name=args.adapter,
        tag=tag,
        action=args.action,
    )

    if args.action == "apply":
        ok = orch.apply_all()
        if ok:
            log.info("")
            log.info(f"Session tag: {orch.tag}")
            log.info(f"Restore with: python main.py session restore --tag {orch.tag}")
    elif args.action == "restore":
        log.info(f"Restoring session: {orch.tag}")
        ok = orch.restore_all()
    elif args.action == "backup":
        ok = orch.backup_all()
    elif args.action == "verify":
        log.info(f"Verifying session: {orch.tag}")
        orch.verify_all()
        ok = True
    elif args.action == "list":
        sessions = SessionOrchestrator.list_sessions()
        if not sessions:
            log.info("No session backups found.")
        else:
            log.info(f"Found {len(sessions)} session(s), newest first:")
            for s in sessions:
                log.info(f"  {s}")
        ok = True
    else:
        log.error(f"Unknown session action: {args.action}")
        return 1

    return 0 if ok else 1

def cmd_backup(args) -> int:
    bm = BackupManager(tag=args.tag)
    for name in args.modules:
        try:
            mod = _build_module(name, args)
        except ValueError as e:
            log.error(str(e))
            continue
        data = mod.backup()
        bm.save(name, data)
    log.info("Backup complete.")
    return 0

def cmd_repair(args) -> int:
    for name in args.modules:
        try:
            mod = _build_module(name, args)
        except ValueError as e:
            log.error(str(e))
            continue
        log.info(f"--- Repairing {name} ---")
        try:
            mod.repair()
            log.info(f"{name}: now = {mod.verify()}")
        except Exception as e:
            log.error(f"{name} repair failed: {e}")
            return 1
    return 0

def cmd_apply(args) -> int:
    for name in args.modules:
        try:
            mod = _build_module(name, args)
        except ValueError as e:
            log.error(str(e))
            continue
        log.info(f"--- Applying {name} ---")
        try:
            if name == "volume_id":
                mod.apply(args.value, force=getattr(args, "force", False))
            else:
                mod.apply(args.value)
            log.info(f"{name}: now = {mod.verify()}")
        except Exception as e:
            log.error(f"{name} failed: {e}")
            return 1
    return 0



def cmd_restore(args) -> int:
    bm = BackupManager(tag=args.tag)
    for name in args.modules:
        try:
            mod = _build_module(name, args)
        except ValueError as e:
            log.error(str(e))
            continue
        data = bm.load(name)
        if data is None:
            log.warning(f"No backup found for {name}, skipping.")
            continue
        log.info(f"--- Restoring {name} ---")
        try:
            mod.restore(data)
            log.info(f"{name}: now = {mod.verify()}")
        except Exception as e:
            log.error(f"{name} restore failed: {e}")
            return 1
    return 0

def cmd_reset(args) -> int:
    """
    Restore all modules from the 'default' backup (factory originals).
    """
    log.info("Restoring all modules to factory originals from tag 'default'.")
    bm = BackupManager(tag="default")
    for name in ["machine_guid", "mac", "dhcp_id", "hostname"]:
        data = bm.load(name)
        if data is None:
            log.warning(f"No 'default' backup for {name}. Skipping.")
            continue
        try:
            mod = _build_module(name, args)
            log.info(f"--- Resetting {name} ---")
            mod.restore(data)
            log.info(f"{name}: {mod.verify()}")
        except Exception as e:
            log.error(f"{name} reset failed: {e}")
            return 1
    log.info("Reset complete. Reboot recommended for hostname/env refresh.")
    return 0

def cmd_verify(args) -> int:
    for name in args.modules:
        try:
            mod = _build_module(name, args)
        except ValueError as e:
            log.error(str(e))
            continue
        try:
            log.info(f"{name}: {mod.verify()}")
        except Exception as e:
            log.error(f"{name}: verify failed: {e}")
            return 1
    return 0


def _add_common_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--adapter", default="Wi-Fi",
                   help="Target network adapter (MAC + DHCP modules).")
    p.add_argument("--drive", default="D",
                   help="Target drive letter (volume_id module). Default: D")
    p.add_argument("--tag", default="default",
                   help="Backup session tag.")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="spoof_tool",
        description="Deep hardware identifier spoofing tool.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    sub = parser.add_subparsers(dest="command", required=True)
    
    p_reset = sub.add_parser("reset", help="Restore all modules to factory (from 'default' backup)")
    _add_common_flags(p_reset)
    p_reset.set_defaults(func=cmd_reset)
    
    p_session = sub.add_parser("session", help="Orchestrate all modules")
    p_session.add_argument(
        "action",
        choices=["apply", "restore", "backup", "verify", "list"],
        help="Session action",
    )
    _add_common_flags(p_session)
    p_session.set_defaults(func=cmd_session)
    
    p_repair = sub.add_parser("repair", help="Enforce consistency (no primary change)")
    p_repair.add_argument("modules", nargs="+", help="Modules to repair")
    _add_common_flags(p_repair)
    p_repair.set_defaults(func=cmd_repair)

    p_backup = sub.add_parser("backup", help="Save current state")
    p_backup.add_argument("modules", nargs="+", help="Modules to back up")
    _add_common_flags(p_backup)
    p_backup.set_defaults(func=cmd_backup)

    p_apply = sub.add_parser("apply", help="Apply spoof")
    p_apply.add_argument("modules", nargs="+", help="Modules to apply")
    p_apply.add_argument("--value", "-V", default=None, help="Explicit value (optional)")
    p_apply.add_argument("--force", action="store_true",
                     help="Allow dangerous operations (volume_id on system drive).")
    _add_common_flags(p_apply)
    p_apply.set_defaults(func=cmd_apply)

    p_restore = sub.add_parser("restore", help="Restore from backup")
    p_restore.add_argument("modules", nargs="+", help="Modules to restore")
    _add_common_flags(p_restore)
    p_restore.set_defaults(func=cmd_restore)

    p_verify = sub.add_parser("verify", help="Show current values")
    p_verify.add_argument("modules", nargs="+", help="Modules to verify")
    _add_common_flags(p_verify)
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("spoof_tool").setLevel(logging.DEBUG)

    if args.command in ("apply", "restore", "repair", "session", "reset"):
        require_admin(auto_elevate=True)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())