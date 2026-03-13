"""RSA for the SOEN 321 project prototype."""

import hashlib
import secrets

from dataclasses import dataclass
from number_theory import gcd, modexp, modinv, generate_prime


@dataclass
class RSAPublicKey:
    e: int
    n: int


@dataclass
class RSAPrivateKey:
    d: int
    n: int


@dataclass
class RSAKeyPair:
    public: RSAPublicKey
    private: RSAPrivateKey
    p: int
    q: int


def generate_keypair(bits: int = 512, e: int = 65537) -> RSAKeyPair:
    """
    Generate an RSA key pair.
    Num of bits is set to 512 to keep the demo quick and simple.
    Explained in the report that real systems should use larger parameters, typically with 2048 bits.
    """
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break

    n = p * q
    d = modinv(e, phi)
    return RSAKeyPair(
        public=RSAPublicKey(e=e, n=n),
        private=RSAPrivateKey(d=d, n=n),
        p=p,
        q=q,
    )


def encrypt_int(m: int, public_key: RSAPublicKey) -> int:
    if not (0 <= m < public_key.n):
        raise ValueError("Message representative out of range for RSA modulus.")
    return modexp(m, public_key.e, public_key.n)


def decrypt_int(c: int, private_key: RSAPrivateKey) -> int:
    return modexp(c, private_key.d, private_key.n)


# This method is used to hash the plaintext before RSA.
def hash_to_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), byteorder="big")


def sign(data: bytes, private_key: RSAPrivateKey) -> int:
    h = hash_to_int(data) % private_key.n
    return modexp(h, private_key.d, private_key.n)


def verify(data: bytes, signature: int, public_key: RSAPublicKey) -> bool:
    h = hash_to_int(data) % public_key.n
    recovered = modexp(signature, public_key.e, public_key.n)
    return recovered == h
