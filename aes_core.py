"""
AES Core Utilities using PyCryptodome
- AES-CBC with PKCS7 padding
- Base64 encoding for outputs
- 128-bit IV prefixed to the ciphertext
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from typing import Tuple

BLOCK_SIZE = 16  # AES block size in bytes (128 bits)
VALID_KEY_SIZES = {16, 24, 32}  # bytes -> 128/192/256-bit keys


def generate_key(bits: int = 256) -> bytes:
    """
    Generate a random AES key.
    :param bits: 128, 192, or 256
    :return: key bytes
    """
    if bits not in (128, 192, 256):
        raise ValueError("bits must be 128, 192, or 256")
    return get_random_bytes(bits // 8)


def parse_key(key_input: str, encoding: str = "text") -> bytes:
    """
    Parse a key string into raw bytes based on selected encoding.
    :param key_input: the input text
    :param encoding: 'text', 'hex', or 'base64'
    :return: key bytes
    """
    encoding = encoding.lower().strip()
    if encoding == "text":
        key = key_input.encode("utf-8")
    elif encoding == "hex":
        key = bytes.fromhex(key_input.strip())
    elif encoding in ("base64", "b64"):
        key = base64.b64decode(key_input.strip())
    else:
        raise ValueError("encoding must be 'text', 'hex', or 'base64'")
    if len(key) not in VALID_KEY_SIZES:
        raise ValueError(
            f"Invalid AES key length: {len(key)} bytes. Must be 16/24/32 bytes for AES-128/192/256."
        )
    return key


def encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt plaintext (UTF-8) using AES-CBC with PKCS7 padding.
    Returns base64-encoded bytes of (IV || ciphertext).
    """
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pad(plaintext.encode("utf-8"), BLOCK_SIZE)
    ct = cipher.encrypt(padded)
    blob = iv + ct
    return base64.b64encode(blob).decode("utf-8")


def decrypt(b64_blob: str, key: bytes) -> str:
    """
    Decrypt base64-encoded blob produced by encrypt().
    The blob is (IV || ciphertext). Returns UTF-8 plaintext.
    """
    raw = base64.b64decode(b64_blob)
    if len(raw) < BLOCK_SIZE:
        raise ValueError("Ciphertext too short to contain IV.")
    iv, ct = raw[:BLOCK_SIZE], raw[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ct)
    pt = unpad(padded, BLOCK_SIZE)
    return pt.decode("utf-8")


def encrypt_bytes(plaintext_bytes: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt raw bytes; returns (iv, ciphertext) as bytes.
    Useful when not using base64 container.
    """
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pad(plaintext_bytes, BLOCK_SIZE)
    ct = cipher.encrypt(padded)
    return iv, ct


def decrypt_bytes(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt raw bytes given IV and ciphertext; returns plaintext bytes.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, BLOCK_SIZE)
