"""
Schema definitions for encrypted message payloads used in the API.
"""
from __future__ import annotations

from pydantic import BaseModel


class EncryptedPackage(BaseModel):
    """
    Represents a hybrid-encrypted message containing:
    - AES-GCM encrypted data, an RSA-encrypted key and an Ed25519 signature
    - All fields are Base64-encoded
    """
    nonce: str
    enc_key: str
    ciphertext: str
    signature: str
    algorithms: dict[str, str] | None = None
