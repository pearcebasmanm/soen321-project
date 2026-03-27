"""Authenticated Diffie-Hellman secure messaging prototype.

Protocol summary:
1. Each user has an RSA key pair for signatures.
2. User1 and User2 run Diffie-Hellman to derive a shared secret.
3. DH public values are signed with RSA to mitigate the man-in-the-middle
   attack discussed in the course slides.
4. A session key is derived from the DH secret and nonces using SHA-256.
5. Messages are encrypted using a hash-based XOR keystream.
6. Ciphertext metadata is signed by the sender.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass
from dataclasses_json import dataclass_json
from typing import Any

from dh import (
    DHParameters,
    compute_public_value,
    compute_shared_secret,
    generate_private_exponent,
)
from rsa import RSAKeyPair, RSAPublicKey, sign, verify


def _b(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, byteorder="big")


def _derive_session_key(shared_secret: int, nonce_a: bytes, nonce_b: bytes) -> bytes:
    seed = _b(shared_secret) + nonce_a + nonce_b
    return hashlib.sha256(seed).digest()


def _keystream(session_key: bytes, nbytes: int) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < nbytes:
        block = hashlib.sha256(session_key + counter.to_bytes(4, "big")).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:nbytes])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass_json
@dataclass
class LocalParty:
    name: str
    rsa_keys: RSAKeyPair


@dataclass_json
@dataclass
class RemoteParty:
    name: str
    rsa_public_keys: RSAPublicKey


@dataclass_json
@dataclass
class FirstPassMessage:
    sender: str
    receiver: str
    public_value: int
    nonce_a: str
    signature: int


@dataclass_json
@dataclass
class SecondPassMessage:
    sender: str
    receiver: str
    public_value: int
    nonce_a: str
    nonce_b: str
    signature: int


@dataclass_json
@dataclass
class SessionState:
    params: DHParameters
    initiator: str
    responder: str
    nonce_a: bytes
    nonce_b: bytes
    public_a: int
    public_b: int
    shared_secret: int
    session_key: bytes


def initiate_session(
    initiator: LocalParty, responder: RemoteParty, params: DHParameters
) -> tuple[FirstPassMessage, int]:
    a = generate_private_exponent(params.p)
    A = compute_public_value(a, params)
    nonce_a = secrets.token_bytes(16)
    payload = f"{initiator.name}|{responder.name}|{A}|{nonce_a.hex()}".encode()
    sigma_a = sign(payload, initiator.rsa_keys.private)
    message_1 = FirstPassMessage(
        sender=initiator.name,
        receiver=responder.name,
        public_value=A,  # g^a
        nonce_a=nonce_a.hex(),
        signature=sigma_a,
    )
    return message_1, a


def respond_session(
    responder: LocalParty,
    initiator: RemoteParty,
    params: DHParameters,
    message_1: FirstPassMessage,
) -> tuple[SecondPassMessage, int, SessionState]:
    payload = f"{message_1.sender}|{message_1.receiver}|{message_1.public_value}|{message_1.nonce_a}".encode()
    if not verify(payload, message_1.signature, initiator.rsa_public_keys):
        raise ValueError("Responder rejected session initiation: invalid signature")

    b = generate_private_exponent(params.p)
    B = compute_public_value(b, params)
    nonce_b = secrets.token_bytes(16)
    shared_secret = compute_shared_secret(message_1.public_value, b, params)
    session_key = _derive_session_key(
        shared_secret, bytes.fromhex(message_1.nonce_a), nonce_b
    )

    payload_2 = f"{responder.name}|{initiator.name}|{B}|{message_1.nonce_a}|{nonce_b.hex()}".encode()
    sigma_b = sign(payload_2, responder.rsa_keys.private)
    message_2 = SecondPassMessage(
        sender=responder.name,
        receiver=initiator.name,
        public_value=B,  # g^b
        nonce_a=message_1.nonce_a,
        nonce_b=nonce_b.hex(),
        signature=sigma_b,
    )

    state = SessionState(
        params=params,
        initiator=initiator.name,
        responder=responder.name,
        nonce_a=bytes.fromhex(message_1.nonce_a),
        nonce_b=nonce_b,
        public_a=message_1.public_value,
        public_b=B,
        shared_secret=shared_secret,
        session_key=session_key,
    )
    return message_2, b, state


def finalize_session(
    initiator: LocalParty,
    responder: RemoteParty,
    params: DHParameters,
    private_a: int,
    message_2: SecondPassMessage,
) -> SessionState:
    payload_2 = f"{message_2.sender}|{message_2.receiver}|{message_2.public_value}|{message_2.nonce_a}|{message_2.nonce_b}".encode()
    if not verify(payload_2, message_2.signature, responder.rsa_public_keys):
        raise ValueError("Initiator rejected response: invalid signature")

    shared_secret = compute_shared_secret(
        message_2.public_value, private_a, params
    )  # (g^b)^a
    nonce_a = bytes.fromhex(message_2.nonce_a)
    nonce_b = bytes.fromhex(message_2.nonce_b)
    session_key = _derive_session_key(shared_secret, nonce_a, nonce_b)

    public_a = compute_public_value(private_a, params)
    return SessionState(
        params=params,
        initiator=initiator.name,
        responder=responder.name,
        nonce_a=nonce_a,
        nonce_b=nonce_b,
        public_a=public_a,
        public_b=message_2.public_value,
        shared_secret=shared_secret,
        session_key=session_key,
    )


def encrypt_message(
    sender: LocalParty, session: SessionState, plaintext: str
) -> dict[str, Any]:
    data = plaintext.encode("utf-8")
    ks = _keystream(session.session_key, len(data))
    ciphertext = _xor_bytes(data, ks)

    header = {
        "sender": sender.name,
        "receiver_pair": f"{session.initiator}<->{session.responder}",
        "nonce_a": session.nonce_a.hex(),
        "nonce_b": session.nonce_b.hex(),
        "length": len(data),
    }
    header_bytes = json.dumps(header, sort_keys=True).encode()
    signature = sign(header_bytes + ciphertext, sender.rsa_keys.private)
    return {
        "header": header,
        "ciphertext_hex": ciphertext.hex(),
        "signature": signature,
    }


def decrypt_message(
    receiver_public_verify_key, session: SessionState, packet: dict[str, Any]
) -> str:
    header_bytes = json.dumps(packet["header"], sort_keys=True).encode()
    ciphertext = bytes.fromhex(packet["ciphertext_hex"])
    if not verify(
        header_bytes + ciphertext, packet["signature"], receiver_public_verify_key
    ):
        raise ValueError("Invalid message signature")

    ks = _keystream(session.session_key, len(ciphertext))
    plaintext = _xor_bytes(ciphertext, ks)
    return plaintext.decode("utf-8")


def packet_digest(packet: dict[str, Any]) -> str:
    serialized = json.dumps(packet, sort_keys=True).encode()
    return hashlib.sha256(serialized).hexdigest()
