"""Tests for backup_crypt.crypto — encryption, decryption, and tamper detection."""

import pytest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from backup_crypt.crypto import (
    encrypt_file,
    decrypt_file,
    derive_key,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    HEADER_SIZE,
)

PASSWORD = b"correct-horse-battery-staple"
WRONG_PW = b"wrong-password"


def write_tmp(tmp_path: Path, name: str, content: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_returns_32_bytes(self):
        import os
        salt = os.urandom(SALT_SIZE)
        key = derive_key(PASSWORD, salt)
        assert len(key) == 32

    def test_same_password_same_salt_is_deterministic(self):
        import os
        salt = os.urandom(SALT_SIZE)
        k1 = derive_key(PASSWORD, salt)
        k2 = derive_key(PASSWORD, salt)
        assert k1 == k2

    def test_different_salts_produce_different_keys(self):
        import os
        salt1, salt2 = os.urandom(SALT_SIZE), os.urandom(SALT_SIZE)
        assert derive_key(PASSWORD, salt1) != derive_key(PASSWORD, salt2)

    def test_different_passwords_produce_different_keys(self):
        import os
        salt = os.urandom(SALT_SIZE)
        assert derive_key(PASSWORD, salt) != derive_key(WRONG_PW, salt)


# ---------------------------------------------------------------------------
# Encrypt / Decrypt round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_small_file(self, tmp_path):
        src = write_tmp(tmp_path, "hello.txt", b"Hello, World!")
        enc = tmp_path / "hello.txt.enc"
        dec = tmp_path / "hello_dec.txt"

        encrypt_file(src, enc, PASSWORD)
        decrypt_file(enc, dec, PASSWORD)

        assert dec.read_bytes() == b"Hello, World!"

    def test_empty_file(self, tmp_path):
        src = write_tmp(tmp_path, "empty.txt", b"")
        enc = tmp_path / "empty.enc"
        dec = tmp_path / "empty_dec.txt"

        encrypt_file(src, enc, PASSWORD)
        decrypt_file(enc, dec, PASSWORD)

        assert dec.read_bytes() == b""

    def test_binary_file(self, tmp_path):
        data = bytes(range(256)) * 100
        src = write_tmp(tmp_path, "bin.dat", data)
        enc = tmp_path / "bin.enc"
        dec = tmp_path / "bin_dec.dat"

        encrypt_file(src, enc, PASSWORD)
        decrypt_file(enc, dec, PASSWORD)

        assert dec.read_bytes() == data

    def test_large_file(self, tmp_path):
        data = b"A" * (1024 * 1024)  # 1 MB
        src = write_tmp(tmp_path, "big.dat", data)
        enc = tmp_path / "big.enc"
        dec = tmp_path / "big_dec.dat"

        encrypt_file(src, enc, PASSWORD)
        decrypt_file(enc, dec, PASSWORD)

        assert dec.read_bytes() == data


# ---------------------------------------------------------------------------
# Header structure
# ---------------------------------------------------------------------------

class TestFileFormat:
    def test_encrypted_file_has_correct_header_size(self, tmp_path):
        plaintext = b"test data"
        src = write_tmp(tmp_path, "f.txt", plaintext)
        enc = tmp_path / "f.enc"

        encrypt_file(src, enc, PASSWORD)

        raw = enc.read_bytes()
        assert len(raw) == HEADER_SIZE + len(plaintext)

    def test_unique_nonce_per_file(self, tmp_path):
        """Two encryptions of the same file must use different nonces."""
        src = write_tmp(tmp_path, "f.txt", b"same content")
        enc1 = tmp_path / "f1.enc"
        enc2 = tmp_path / "f2.enc"

        encrypt_file(src, enc1, PASSWORD)
        encrypt_file(src, enc2, PASSWORD)

        raw1, raw2 = enc1.read_bytes(), enc2.read_bytes()
        nonce1 = raw1[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        nonce2 = raw2[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        assert nonce1 != nonce2

    def test_unique_salt_per_file(self, tmp_path):
        src = write_tmp(tmp_path, "f.txt", b"same content")
        enc1 = tmp_path / "f1.enc"
        enc2 = tmp_path / "f2.enc"

        encrypt_file(src, enc1, PASSWORD)
        encrypt_file(src, enc2, PASSWORD)

        salt1 = enc1.read_bytes()[:SALT_SIZE]
        salt2 = enc2.read_bytes()[:SALT_SIZE]
        assert salt1 != salt2


# ---------------------------------------------------------------------------
# Authentication / tamper detection
# ---------------------------------------------------------------------------

class TestTamperDetection:
    def test_wrong_password_raises_invalid_tag(self, tmp_path):
        src = write_tmp(tmp_path, "f.txt", b"secret")
        enc = tmp_path / "f.enc"
        dec = tmp_path / "f_dec.txt"

        encrypt_file(src, enc, PASSWORD)

        with pytest.raises(InvalidTag):
            decrypt_file(enc, dec, WRONG_PW)

    def test_bit_flip_in_ciphertext_raises_invalid_tag(self, tmp_path):
        src = write_tmp(tmp_path, "f.txt", b"tamper me")
        enc = tmp_path / "f.enc"
        dec = tmp_path / "f_dec.txt"

        encrypt_file(src, enc, PASSWORD)

        raw = bytearray(enc.read_bytes())
        raw[-1] ^= 0xFF  # flip last byte of ciphertext
        enc.write_bytes(bytes(raw))

        with pytest.raises(InvalidTag):
            decrypt_file(enc, dec, PASSWORD)

    def test_tampered_file_is_not_written(self, tmp_path):
        """Ensure decrypt_file does not create the output file on InvalidTag."""
        src = write_tmp(tmp_path, "f.txt", b"do not write")
        enc = tmp_path / "f.enc"
        dec = tmp_path / "f_dec.txt"

        encrypt_file(src, enc, PASSWORD)

        raw = bytearray(enc.read_bytes())
        raw[HEADER_SIZE] ^= 0xAB
        enc.write_bytes(bytes(raw))

        with pytest.raises(InvalidTag):
            decrypt_file(enc, dec, PASSWORD)

        assert not dec.exists()

    def test_truncated_file_raises_value_error(self, tmp_path):
        enc = write_tmp(tmp_path, "short.enc", b"\x00" * 10)
        dec = tmp_path / "out.txt"

        with pytest.raises(ValueError, match="too short"):
            decrypt_file(enc, dec, PASSWORD)
