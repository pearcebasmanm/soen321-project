"""Diffie-Hellman primitives for the SOEN 321 project prototype."""

import secrets

from dataclasses import dataclass
from number_theory import modexp


# Using a fixed large prime just for simple demos and tests.
# In the real world, systems need stronger parameter validation.
DEFAULT_P = (1 << 127) - 1
DEFAULT_G = 3


@dataclass
class DHParameters:
    p: int = DEFAULT_P
    g: int = DEFAULT_G


def generate_private_exponent(p: int) -> int:
    return secrets.randbelow(p - 3) + 2


def compute_public_value(private_exponent: int, params: DHParameters) -> int:
    return modexp(params.g, private_exponent, params.p)


def compute_shared_secret(
    peer_public_value: int, private_exponent: int, params: DHParameters
) -> int:
    return modexp(peer_public_value, private_exponent, params.p)
