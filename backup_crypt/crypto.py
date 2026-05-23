"""Cryptographic primitives: AES-256-GCM encryption and PBKDF2-HMAC-SHA256 key derivation.

File format (binary header):
    [ salt 16B ][ nonce 12B ][ auth_tag 16B ][ ciphertext ... ]
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16   # bytes
NONCE_SIZE = 12  # bytes — 96 bits, GCM standard
TAG_SIZE = 16    # bytes — 128-bit auth tag
KEY_SIZE = 32    # bytes — AES-256

HEADER_SIZE = SALT_SIZE + NONCE_SIZE + TAG_SIZE  # 44 bytes


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: UTF-8 encoded passphrase.
        salt: 16-byte random salt, unique per file.

    Returns:
        32-byte derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password)
    return key


def encrypt_file(src: Path, dst: Path, password: bytes) -> None:
    """Encrypt a single file with AES-256-GCM and write to dst.

    A fresh salt and nonce are generated for every file. The derived key is
    deleted from memory immediately after use.

    Args:
        src: Plaintext source file.
        dst: Destination path for the encrypted file.
        password: UTF-8 encoded passphrase.

    Raises:
        OSError: If src cannot be read or dst cannot be written.
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)
    try:
        aesgcm = AESGCM(key)
        plaintext = src.read_bytes()
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    finally:
        del key

    # AESGCM.encrypt appends the 16-byte tag at the end of the ciphertext.
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    tag = ciphertext_with_tag[-TAG_SIZE:]

    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)


def decrypt_file(src: Path, dst: Path, password: bytes) -> None:
    """Decrypt a single file previously encrypted by encrypt_file.

    The GCM authentication tag is verified before any data is written to dst.
    Raises InvalidTag without writing anything if the file has been tampered with.

    Args:
        src: Encrypted source file.
        dst: Destination path for the restored plaintext.
        password: UTF-8 encoded passphrase.

    Raises:
        ValueError: If the file is too short to contain a valid header.
        InvalidTag: If the GCM authentication tag does not match (tampered/corrupt file).
        OSError: If src cannot be read or dst cannot be written.
    """
    data = src.read_bytes()
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"File too short to be a valid encrypted file: {src} ({len(data)} bytes)"
        )

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = data[SALT_SIZE + NONCE_SIZE:HEADER_SIZE]
    ciphertext = data[HEADER_SIZE:]

    key = derive_key(password, salt)
    try:
        aesgcm = AESGCM(key)
        # Re-assemble ciphertext+tag as expected by cryptography's AESGCM.decrypt
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    finally:
        del key

    # Write only after successful authentication
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(plaintext)
