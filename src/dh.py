"""Diffie-Hellman primitives for the SOEN 321 project prototype."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from number_theory import modexp


# Im using a fixed large prime just fro simple demos and tests.
# I think we should explain in the report that in the real world, systems need stronger parameter 
# validation or that it simply works in a more complex way, but that we are just going for 
# simplicity for th purpose of the project.
DEFAULT_P = (1 << 127) - 1  #This is 2^127 - 1, which is prime. 
DEFAULT_G = 3 #g=3 is just  a simple generator choice


@dataclass
class DHParameters:
    p: int = DEFAULT_P
    g: int = DEFAULT_G


def generate_private_exponent(p: int) -> int:
    return secrets.randbelow(p - 3) + 2


def compute_public_value(private_exponent: int, params: DHParameters) -> int:
    return modexp(params.g, private_exponent, params.p)


def compute_shared_secret(peer_public_value: int, private_exponent: int, params: DHParameters) -> int:
    return modexp(peer_public_value, private_exponent, params.p)
