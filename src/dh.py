"""Diffie-Hellman primitives for the SOEN 321 project prototype."""

import secrets

from dataclasses import dataclass
from dataclasses_json import dataclass_json


# A known standard 2048-bit prime from RFC 3526 Group 14: 2048-bit MODP Group
# https://www.rfc-editor.org/rfc/rfc3526#section-3
DEFAULT_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DEFAULT_G = 2


@dataclass_json
@dataclass
class DHParameters:
    p: int = DEFAULT_P
    g: int = DEFAULT_G


def generate_private_exponent(p: int) -> int:
    return (
        secrets.randbelow(p - 3) + 2
    )  # Make sure that the private exponent is in [2, p-2]


def compute_public_value(private_exponent: int, params: DHParameters) -> int:
    return pow(params.g, private_exponent, mod=params.p)


def compute_shared_secret(
    peer_public_value: int, private_exponent: int, params: DHParameters
) -> int:
    return pow(peer_public_value, private_exponent, mod=params.p)
