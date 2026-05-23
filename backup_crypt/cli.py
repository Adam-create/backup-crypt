"""CLI entry point for backup-crypt using argparse."""

import argparse
import getpass
import logging
import sys
from pathlib import Path

from .backup import backup, restore, list_backups
from .utils import setup_logging, err, bold

logger = logging.getLogger(__name__)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="backup-crypt",
        description="Encrypted backup tool — AES-256-GCM + PBKDF2-HMAC-SHA256",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  backup-crypt backup  --source ./docs    --dest /media/usb/backup\n"
            "  backup-crypt restore --source /media/usb/backup --dest ./restored\n"
            "  backup-crypt list    --dest /media/usb/backup\n"
        ),
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    # -- backup ---------------------------------------------------------------
    p_backup = sub.add_parser("backup", help="Encrypt and back up files")
    p_backup.add_argument(
        "--source",
        type=Path,
        required=True,
        metavar="PATH",
        help="Source directory (or file) to back up",
    )
    p_backup.add_argument(
        "--dest",
        type=Path,
        required=True,
        metavar="PATH",
        help="Destination directory for encrypted files",
    )

    # -- restore --------------------------------------------------------------
    p_restore = sub.add_parser("restore", help="Decrypt and restore files")
    p_restore.add_argument(
        "--source",
        type=Path,
        required=True,
        metavar="PATH",
        help="Directory containing the encrypted backup",
    )
    p_restore.add_argument(
        "--dest",
        type=Path,
        required=True,
        metavar="PATH",
        help="Destination directory for restored files",
    )

    # -- list -----------------------------------------------------------------
    p_list = sub.add_parser("list", help="List encrypted files in a backup directory")
    p_list.add_argument(
        "--dest",
        type=Path,
        required=True,
        metavar="PATH",
        help="Directory to scan for encrypted backups",
    )

    return parser.parse_args(argv)


def _require_path(path: Path, label: str) -> bool:
    """Return True if path exists, otherwise print an error and return False."""
    if not path.exists():
        print(err(f"Error: {label} path does not exist: {path}"), file=sys.stderr)
        return False
    return True


def _prompt_password(confirm: bool = False) -> bytes:
    """Prompt for a passphrase via getpass (never echoed).

    Args:
        confirm: If True, ask twice and verify they match.

    Returns:
        UTF-8 encoded passphrase bytes.
    """
    password = getpass.getpass(prompt="Passphrase: ")
    if not password:
        print(err("Error: passphrase must not be empty."), file=sys.stderr)
        sys.exit(1)

    if confirm:
        confirm_pw = getpass.getpass(prompt="Confirm passphrase: ")
        if password != confirm_pw:
            print(err("Error: passphrases do not match."), file=sys.stderr)
            sys.exit(1)

    encoded = password.encode("utf-8")
    del password
    return encoded


def main(argv: list[str] | None = None) -> None:
    """Main CLI entry point.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).
    """
    args = _parse_args(argv)
    setup_logging(args.verbose)

    if args.command == "list":
        if not _require_path(args.dest, "--dest"):
            sys.exit(1)
        list_backups(args.dest)
        return

    if args.command == "backup":
        if not _require_path(args.source, "--source"):
            sys.exit(1)
        args.dest.mkdir(parents=True, exist_ok=True)
        print(bold("backup-crypt — Encrypted Backup"))
        password = _prompt_password(confirm=True)
        try:
            result = backup(args.source, args.dest, password)
        finally:
            del password

        if result.failed and result.succeeded == 0:
            sys.exit(1)
        return

    if args.command == "restore":
        if not _require_path(args.source, "--source"):
            sys.exit(1)
        args.dest.mkdir(parents=True, exist_ok=True)
        print(bold("backup-crypt — Restore"))
        password = _prompt_password(confirm=False)
        try:
            result = restore(args.source, args.dest, password)
        finally:
            del password

        if result.failed > 0:
            sys.exit(1)
        return


if __name__ == "__main__":
    main()
