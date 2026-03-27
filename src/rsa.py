"""RSA for the SOEN 321 project prototype."""

import hashlib
import math

from dataclasses import dataclass
from dataclasses_json import dataclass_json
from number_theory import generate_prime


@dataclass_json
@dataclass
class RSAPublicKey:
    e: int
    n: int


@dataclass_json
@dataclass
class RSAPrivateKey:
    d: int
    n: int


@dataclass_json
@dataclass
class RSAKeyPair:
    public: RSAPublicKey
    private: RSAPrivateKey


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
        if math.gcd(e, phi) == 1:
            break

    n = p * q
    d = pow(e, -1, mod=phi)
    return RSAKeyPair(
        public=RSAPublicKey(e=e, n=n),
        private=RSAPrivateKey(d=d, n=n),
    )


def encrypt_int(m: int, public_key: RSAPublicKey) -> int:
    if not (0 <= m < public_key.n):
        raise ValueError("Message representative out of range for RSA modulus.")
    return pow(m, public_key.e, mod=public_key.n)


def decrypt_int(c: int, private_key: RSAPrivateKey) -> int:
    return pow(c, private_key.d, mod=private_key.n)


# This method is used to hash the plaintext before RSA.
def hash_to_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), byteorder="big")


def sign(data: bytes, private_key: RSAPrivateKey) -> int:
    h = hash_to_int(data) % private_key.n
    return pow(h, private_key.d, mod=private_key.n)


def verify(data: bytes, signature: int, public_key: RSAPublicKey) -> bool:
    h = hash_to_int(data) % public_key.n
    recovered = pow(signature, public_key.e, public_key.n)
    return recovered == h
