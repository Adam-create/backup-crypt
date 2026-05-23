"""Tests for backup_crypt.backup — backup, restore, and list operations."""

import pytest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from backup_crypt.backup import backup, restore, list_backups, ENCRYPTED_SUFFIX
from backup_crypt.crypto import HEADER_SIZE

PASSWORD = b"test-passphrase-42"


def build_source_tree(root: Path) -> dict[str, bytes]:
    """Create a sample directory tree and return {relative_path: content}."""
    files = {
        "doc.txt": b"This is a document.",
        "subdir/notes.md": b"# Notes\n\nSome notes here.",
        "subdir/data.bin": bytes(range(128)),
        "empty.txt": b"",
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return files


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

class TestBackup:
    def test_all_files_are_encrypted(self, tmp_path):
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        files = build_source_tree(src)

        result = backup(src, dst, PASSWORD)

        assert result.total == len(files)
        assert result.succeeded == len(files)
        assert result.failed == 0

    def test_encrypted_files_have_enc_suffix(self, tmp_path):
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        build_source_tree(src)

        backup(src, dst, PASSWORD)

        enc_files = list(dst.rglob(f"*{ENCRYPTED_SUFFIX}"))
        assert len(enc_files) == 4

    def test_directory_tree_is_preserved(self, tmp_path):
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        build_source_tree(src)

        backup(src, dst, PASSWORD)

        assert (dst / f"subdir/notes.md{ENCRYPTED_SUFFIX}").exists()
        assert (dst / f"subdir/data.bin{ENCRYPTED_SUFFIX}").exists()

    def test_encrypted_file_is_larger_than_plaintext_by_header(self, tmp_path):
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        content = b"hello backup"
        (src / "f.txt").parent.mkdir(parents=True, exist_ok=True)
        (src / "f.txt").write_bytes(content)

        backup(src, dst, PASSWORD)

        enc_file = dst / f"f.txt{ENCRYPTED_SUFFIX}"
        assert enc_file.stat().st_size == HEADER_SIZE + len(content)

    def test_empty_source_returns_zero_total(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        dst = tmp_path / "dst"

        result = backup(src, dst, PASSWORD)

        assert result.total == 0


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

class TestRestore:
    def test_round_trip_restores_content(self, tmp_path):
        src = tmp_path / "src"
        dst_enc = tmp_path / "enc"
        dst_dec = tmp_path / "dec"
        files = build_source_tree(src)

        backup(src, dst_enc, PASSWORD)
        restore(dst_enc, dst_dec, PASSWORD)

        for rel, content in files.items():
            assert (dst_dec / rel).read_bytes() == content

    def test_wrong_password_fails_all_files(self, tmp_path):
        src = tmp_path / "src"
        dst_enc = tmp_path / "enc"
        dst_dec = tmp_path / "dec"
        build_source_tree(src)

        backup(src, dst_enc, PASSWORD)
        result = restore(dst_enc, dst_dec, b"wrong-pw")

        assert result.failed == result.total
        assert result.succeeded == 0

    def test_tampered_file_is_counted_as_failed(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "f.txt").write_bytes(b"sensitive data")
        dst_enc = tmp_path / "enc"
        dst_dec = tmp_path / "dec"

        backup(src, dst_enc, PASSWORD)

        # Corrupt the encrypted file
        enc_file = dst_enc / f"f.txt{ENCRYPTED_SUFFIX}"
        raw = bytearray(enc_file.read_bytes())
        raw[-1] ^= 0xFF
        enc_file.write_bytes(bytes(raw))

        result = restore(dst_enc, dst_dec, PASSWORD)

        assert result.failed == 1
        assert result.succeeded == 0
        # Plaintext must NOT be written
        assert not (dst_dec / "f.txt").exists()

    def test_restore_no_enc_files_returns_zero(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "plain.txt").write_bytes(b"not encrypted")

        result = restore(src, tmp_path / "dec", PASSWORD)

        assert result.total == 0


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

class TestListBackups:
    def test_lists_enc_files(self, tmp_path, capsys):
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        build_source_tree(src)
        backup(src, dst, PASSWORD)

        list_backups(dst)

        captured = capsys.readouterr()
        assert ".enc" in captured.out
        assert "4" in captured.out  # file count

    def test_empty_directory_warns(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()

        list_backups(empty)

        captured = capsys.readouterr()
        assert "No encrypted" in captured.out
