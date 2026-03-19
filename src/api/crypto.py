"""
Core Cryptographic functions for the API.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_project_root = Path(__file__).parent.parent.parent
KEYS_DIR = _project_root / "keys"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def ensure_keys_dir() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def generate_demo_keys() -> None:
    """
    Generate demo keys for:
    - Bob: RSA keypair for decrypting the AES session key
    - Alice: Ed25519 keypair for signing messages

    Files created:
    - keys/bob_rsa_private.pem
    - keys/bob_rsa_public.pem
    - keys/alice_sign_private.pem
    - keys/alice_sign_public.pem
    """
    ensure_keys_dir()

    _encoding = serialization.Encoding.PEM
    _priv_format = serialization.PrivateFormat.PKCS8
    _pub_format = serialization.PublicFormat.SubjectPublicKeyInfo

    #
    # Bob RSA keypair
    bob_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob_public = bob_private.public_key()

    bob_private_pem = bob_private.private_bytes(encoding=_encoding, format=_priv_format,
                                                encryption_algorithm=serialization.NoEncryption())
    bob_public_pem = bob_public.public_bytes(encoding=_encoding, format=_pub_format)

    #
    # Alice Ed25519 keypair
    alice_private = ed25519.Ed25519PrivateKey.generate()
    alice_public = alice_private.public_key()

    alice_private_pem = alice_private.private_bytes(encoding=_encoding, format=_priv_format,
                                                    encryption_algorithm=serialization.NoEncryption())
    alice_public_pem = alice_public.public_bytes(encoding=_encoding, format=_pub_format)

    (KEYS_DIR / "bob_rsa_private.pem").write_bytes(bob_private_pem)
    (KEYS_DIR / "bob_rsa_public.pem").write_bytes(bob_public_pem)
    (KEYS_DIR / "alice_sign_private.pem").write_bytes(alice_private_pem)
    (KEYS_DIR / "alice_sign_public.pem").write_bytes(alice_public_pem)


def load_bob_rsa_public_key():
    return serialization.load_pem_public_key((KEYS_DIR / "bob_rsa_public.pem").read_bytes())


def load_bob_rsa_private_key():
    return serialization.load_pem_private_key((KEYS_DIR / "bob_rsa_private.pem").read_bytes(), password=None)


def load_alice_sign_private_key():
    key = serialization.load_pem_private_key((KEYS_DIR / "alice_sign_private.pem").read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("Loaded Alice signing private key is not Ed25519")

    return key


def load_alice_sign_public_key():
    key = serialization.load_pem_public_key((KEYS_DIR / "alice_sign_public.pem").read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("Loaded Alice signing public key is not Ed25519")

    return key


def encrypt_and_sign(plaintext: bytes) -> dict[str, Any]:
    """
    Alice-side operation:
    1. Generate random AES-256 key
    2. Encrypt plaintext using AES-GCM
    3. Encrypt AES key with Bob's RSA public key
    4. Sign (nonce || enc_key || ciphertext) with Alice's private signing key

    Returns a JSON-serializable package.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    bob_public = load_bob_rsa_public_key()
    alice_private = load_alice_sign_private_key()

    # AES-256-GCM
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Encrypt AES key for Bob
    enc_key = bob_public.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )

    # Sign package contents
    to_sign = nonce + enc_key + ciphertext
    signature = alice_private.sign(to_sign)

    return {
        "algorithms": {
            # TODO: This can be changed
            "data": "AES-256-GCM",
            "key_wrap": "RSA-2048-OAEP-SHA256",
            "signature": "Ed25519"
        },
        "nonce": b64e(nonce),
        "enc_key": b64e(enc_key),
        "ciphertext": b64e(ciphertext),
        "signature": b64e(signature)
    }


def verify_and_decrypt(package: dict[str, Any]) -> bytes:
    """
    Bob-side operation:
    1. Verify Alice's signature
    2. Decrypt AES key with Bob's private RSA key
    3. Decrypt ciphertext with AES-GCM

    Returns plaintext bytes.
    """
    required_fields = {"nonce", "enc_key", "ciphertext", "signature"}
    missing = required_fields - set(package.keys())
    if missing:
        raise ValueError(f"Package missing required fields: {sorted(missing)}")

    nonce = b64d(package["nonce"])
    enc_key = b64d(package["enc_key"])
    ciphertext = b64d(package["ciphertext"])
    signature = b64d(package["signature"])

    alice_public = load_alice_sign_public_key()
    bob_private = load_bob_rsa_private_key()

    # Verify signature first
    to_verify = nonce + enc_key + ciphertext
    alice_public.verify(signature, to_verify)

    # Decrypt AES key
    aes_key = bob_private.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )

    # Decrypt message
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext


def tamper_ciphertext(package: dict[str, Any]) -> dict[str, Any]:
    """
    Utility for demo/testing.
    Flips one bit in ciphertext so verification/decryption should fail.
    """
    modified = dict(package)
    ciphertext = bytearray(b64d(modified["ciphertext"]))

    if not ciphertext:
        raise ValueError("Ciphertext is empty and cannot be tampered with")

    ciphertext[0] ^= 1
    modified["ciphertext"] = b64e(bytes(ciphertext))
    return modified
