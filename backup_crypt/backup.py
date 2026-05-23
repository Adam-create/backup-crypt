"""Backup and restore logic: orchestrates per-file encryption/decryption."""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from tqdm import tqdm
from cryptography.exceptions import InvalidTag

from .crypto import encrypt_file, decrypt_file
from .utils import collect_files, human_size, ok, warn, err, bold

logger = logging.getLogger(__name__)

ENCRYPTED_SUFFIX = ".enc"


@dataclass
class BackupResult:
    """Summary of a backup or restore operation."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    total_bytes: int = 0
    errors: list[tuple[Path, str]] = field(default_factory=list)
    elapsed: float = 0.0


def backup(source: Path, dest: Path, password: bytes) -> BackupResult:
    """Encrypt all files under source and write them to dest.

    The directory tree is preserved relative to source. Each encrypted file
    gets the `.enc` extension appended.

    Args:
        source: Source directory (or single file) to back up.
        dest: Destination root directory on external storage.
        password: UTF-8 encoded passphrase.

    Returns:
        BackupResult with counts and timing.
    """
    files = collect_files(source)
    result = BackupResult(total=len(files))
    start = time.monotonic()

    if not files:
        logger.warning(warn(f"No files found under {source}"))
        return result

    source_root = source if source.is_dir() else source.parent

    print(bold(f"\nBacking up {result.total} file(s) from {source} → {dest}\n"))

    with tqdm(
        total=result.total,
        unit="file",
        ncols=80,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
    ) as bar:
        for src_file in files:
            rel = src_file.relative_to(source_root)
            dst_file = dest / rel
            dst_file = dst_file.with_suffix(dst_file.suffix + ENCRYPTED_SUFFIX)

            bar.set_description(f"  {rel.name[:40]:<40}")
            try:
                encrypt_file(src_file, dst_file, password)
                result.succeeded += 1
                result.total_bytes += src_file.stat().st_size
            except Exception as exc:
                result.failed += 1
                result.errors.append((src_file, str(exc)))
                logger.debug(err(f"Failed to encrypt {src_file}: {exc}"))
            finally:
                bar.update(1)

    result.elapsed = time.monotonic() - start
    _print_summary("Backup", result)
    return result


def restore(source: Path, dest: Path, password: bytes) -> BackupResult:
    """Decrypt all `.enc` files under source and restore them to dest.

    Files that fail authentication (InvalidTag) are skipped and reported.
    No partial plaintext is ever written for a file with an invalid tag.

    Args:
        source: Root of the encrypted backup directory.
        dest: Destination directory for the restored files.
        password: UTF-8 encoded passphrase.

    Returns:
        BackupResult with counts and timing.
    """
    all_files = collect_files(source)
    enc_files = [f for f in all_files if f.suffix == ENCRYPTED_SUFFIX]
    result = BackupResult(total=len(enc_files))
    start = time.monotonic()

    if not enc_files:
        logger.warning(warn(f"No encrypted files (*.enc) found under {source}"))
        return result

    print(bold(f"\nRestoring {result.total} file(s) from {source} → {dest}\n"))

    with tqdm(
        total=result.total,
        unit="file",
        ncols=80,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
    ) as bar:
        for enc_file in enc_files:
            rel = enc_file.relative_to(source)
            # Strip the .enc suffix to recover the original filename
            original_name = rel.with_suffix("") if rel.suffix == ENCRYPTED_SUFFIX else rel
            dst_file = dest / original_name

            bar.set_description(f"  {enc_file.name[:40]:<40}")
            try:
                decrypt_file(enc_file, dst_file, password)
                result.succeeded += 1
                result.total_bytes += dst_file.stat().st_size
            except InvalidTag:
                result.failed += 1
                msg = "Authentication failed — file may be corrupted or tampered with"
                result.errors.append((enc_file, msg))
                logger.debug(err(f"{enc_file}: {msg}"))
            except ValueError as exc:
                result.failed += 1
                result.errors.append((enc_file, str(exc)))
                logger.debug(err(f"{enc_file}: {exc}"))
            except Exception as exc:
                result.failed += 1
                result.errors.append((enc_file, str(exc)))
                logger.debug(err(f"Failed to decrypt {enc_file}: {exc}"))
            finally:
                bar.update(1)

    result.elapsed = time.monotonic() - start
    _print_summary("Restore", result)
    return result


def list_backups(dest: Path) -> None:
    """Print a human-readable list of encrypted backup files found under dest.

    Args:
        dest: Root directory to scan for `.enc` files.
    """
    enc_files = [f for f in collect_files(dest) if f.suffix == ENCRYPTED_SUFFIX]

    if not enc_files:
        print(warn(f"No encrypted backups found in {dest}"))
        return

    print(bold(f"\nEncrypted backups in {dest}:\n"))
    total_bytes = 0
    for f in enc_files:
        size = f.stat().st_size
        total_bytes += size
        print(f"  {ok('✓')}  {f.relative_to(dest)}  ({human_size(size)})")

    print(
        f"\n  {len(enc_files)} file(s) — {human_size(total_bytes)} total\n"
    )


def _print_summary(operation: str, result: BackupResult) -> None:
    """Print a formatted operation summary to stdout."""
    print()
    print(bold(f"─── {operation} summary ──────────────────────────"))
    print(f"  Files processed : {result.total}")
    print(f"  {ok('Succeeded')}      : {result.succeeded}")
    if result.failed:
        print(f"  {err('Failed')}         : {result.failed}")
    print(f"  Data            : {human_size(result.total_bytes)}")
    print(f"  Duration        : {result.elapsed:.2f}s")

    if result.errors:
        print()
        print(err("  Errors:"))
        for path, msg in result.errors:
            print(f"    • {path.name}: {msg}")

    print()
