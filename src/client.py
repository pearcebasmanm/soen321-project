import asyncio
import json
import httpx
import websockets
from typing import Optional, Callable
from dataclasses import dataclass

from rsa import generate_keypair, RSAKeyPair, sign, verify
from dh import DHParameters, generate_private_exponent, compute_public_value, compute_shared_secret
from secure_messaging import (
    _derive_session_key, encrypt_message, decrypt_message,
    Party, SessionState
)
import secrets

DEFAULT_DH_PARAMS = DHParameters(
    p=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    g=2
)

@dataclass
class ActiveSession:
    session_id: str
    peer: str
    state: SessionState
    peer_public_key: tuple[int, int]

class SecureClient:
    def __init__(self, server_url: str, username: str):
        self.server_url = server_url.rstrip("/")
        self.ws_url = server_url.replace("http", "ws") + f"/ws/{username}"
        self.username = username
        self.rsa_keys: Optional[RSAKeyPair] = None
        self.sessions: dict[str, ActiveSession] = {}
        self.pending_private_keys: dict[str, int] = {}
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.message_handler: Optional[Callable] = None
        self.session_handler: Optional[Callable] = None

    async def register(self):
        self.rsa_keys = generate_keypair(bits=512)
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{self.server_url}/register", json={
                "username": self.username,
                "public_key_n": self.rsa_keys.public[0],
                "public_key_e": self.rsa_keys.public[1]
            })
            if resp.status_code != 200:
                raise Exception(f"Registration failed: {resp.text}")
        return self.rsa_keys

    async def get_user_public_key(self, username: str) -> tuple[int, int]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.server_url}/user/{username}")
            if resp.status_code != 200:
                raise Exception(f"User not found: {username}")
            data = resp.json()
            return (data["public_key_n"], data["public_key_e"])

    async def list_users(self) -> list:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.server_url}/users")
            return resp.json()["users"]

    async def connect_websocket(self):
        self.ws = await websockets.connect(self.ws_url)
        asyncio.create_task(self._listen())

    async def _listen(self):
        try:
            async for message in self.ws:
                data = json.loads(message)
                await self._handle_message(data)
        except websockets.ConnectionClosed:
            pass

    async def _handle_message(self, data: dict):
        msg_type = data.get("type")

        if msg_type == "session_request":
            if self.session_handler:
                await self.session_handler("request", data)

        elif msg_type == "session_response":
            session_id = data["session_id"]
            if session_id in self.pending_private_keys:
                await self._finalize_session(session_id, data["message_2"])

        elif msg_type == "session_finalized":
            if self.session_handler:
                await self.session_handler("finalized", data)

        elif msg_type == "encrypted_message":
            sender = data["sender"]
            session = self._find_session_with_peer(sender)
            if session and self.message_handler:
                peer_public = session.peer_public_key
                plaintext = decrypt_message(peer_public, session.state, {
                    "header": data["header"],
                    "ciphertext_hex": data["ciphertext_hex"],
                    "signature": data["signature"]
                })
                await self.message_handler(sender, plaintext)

    def _find_session_with_peer(self, peer: str) -> Optional[ActiveSession]:
        for session in self.sessions.values():
            if session.peer == peer:
                return session
        return None

    async def initiate_session(self, peer: str):
        peer_public = await self.get_user_public_key(peer)
        
        private_a = generate_private_exponent(DEFAULT_DH_PARAMS.p)
        public_a = compute_public_value(private_a, DEFAULT_DH_PARAMS)
        nonce_a = secrets.token_bytes(16)
        
        payload = f"{self.username}|{peer}|{public_a}|{nonce_a.hex()}".encode()
        signature = sign(payload, self.rsa_keys.private)
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{self.server_url}/session/initiate", json={
                "sender": self.username,
                "receiver": peer,
                "public_value": public_a,
                "nonce_a": nonce_a.hex(),
                "signature": signature
            })
            data = resp.json()
            session_id = data["session_id"]
        
        self.pending_private_keys[session_id] = private_a
        return session_id

    async def respond_to_session(self, session_id: str, message_1: dict):
        initiator = message_1["sender"]
        initiator_public = await self.get_user_public_key(initiator)
        
        payload = f"{message_1['sender']}|{message_1['receiver']}|{message_1['public_value']}|{message_1['nonce_a']}".encode()
        if not verify(payload, message_1["signature"], initiator_public):
            raise ValueError("Invalid session initiation signature")
        
        private_b = generate_private_exponent(DEFAULT_DH_PARAMS.p)
        public_b = compute_public_value(private_b, DEFAULT_DH_PARAMS)
        nonce_b = secrets.token_bytes(16)
        
        shared_secret = compute_shared_secret(message_1["public_value"], private_b, DEFAULT_DH_PARAMS)
        nonce_a_bytes = bytes.fromhex(message_1["nonce_a"])
        session_key = _derive_session_key(shared_secret, nonce_a_bytes, nonce_b)
        
        payload_2 = f"{self.username}|{initiator}|{public_b}|{message_1['nonce_a']}|{nonce_b.hex()}".encode()
        signature = sign(payload_2, self.rsa_keys.private)
        
        async with httpx.AsyncClient() as client:
            await client.post(f"{self.server_url}/session/{session_id}/respond", json={
                "sender": self.username,
                "receiver": initiator,
                "public_value": public_b,
                "nonce_a": message_1["nonce_a"],
                "nonce_b": nonce_b.hex(),
                "signature": signature
            })
        
        state = SessionState(
            params=DEFAULT_DH_PARAMS,
            initiator=initiator,
            responder=self.username,
            nonce_a=nonce_a_bytes,
            nonce_b=nonce_b,
            public_a=message_1["public_value"],
            public_b=public_b,
            shared_secret=shared_secret,
            session_key=session_key
        )
        
        self.sessions[session_id] = ActiveSession(
            session_id=session_id,
            peer=initiator,
            state=state,
            peer_public_key=initiator_public
        )

    async def _finalize_session(self, session_id: str, message_2: dict):
        private_a = self.pending_private_keys.pop(session_id)
        peer = message_2["sender"]
        peer_public = await self.get_user_public_key(peer)
        
        payload_2 = f"{message_2['sender']}|{message_2['receiver']}|{message_2['public_value']}|{message_2['nonce_a']}|{message_2['nonce_b']}".encode()
        if not verify(payload_2, message_2["signature"], peer_public):
            raise ValueError("Invalid session response signature")
        
        shared_secret = compute_shared_secret(message_2["public_value"], private_a, DEFAULT_DH_PARAMS)
        nonce_a = bytes.fromhex(message_2["nonce_a"])
        nonce_b = bytes.fromhex(message_2["nonce_b"])
        session_key = _derive_session_key(shared_secret, nonce_a, nonce_b)
        
        public_a = compute_public_value(private_a, DEFAULT_DH_PARAMS)
        state = SessionState(
            params=DEFAULT_DH_PARAMS,
            initiator=self.username,
            responder=peer,
            nonce_a=nonce_a,
            nonce_b=nonce_b,
            public_a=public_a,
            public_b=message_2["public_value"],
            shared_secret=shared_secret,
            session_key=session_key
        )
        
        self.sessions[session_id] = ActiveSession(
            session_id=session_id,
            peer=peer,
            state=state,
            peer_public_key=peer_public
        )
        
        async with httpx.AsyncClient() as client:
            await client.post(f"{self.server_url}/session/{session_id}/finalize")
        
        if self.session_handler:
            await self.session_handler("established", {"session_id": session_id, "peer": peer})

    async def send_message(self, peer: str, plaintext: str):
        session = self._find_session_with_peer(peer)
        if not session:
            raise ValueError(f"No active session with {peer}")
        
        party = Party(name=self.username, rsa_keys=self.rsa_keys)
        packet = encrypt_message(party, session.state, plaintext)
        
        if self.ws:
            await self.ws.send(json.dumps({
                "type": "message",
                "receiver": peer,
                "header": packet["header"],
                "ciphertext_hex": packet["ciphertext_hex"],
                "signature": packet["signature"]
            }))
        else:
            async with httpx.AsyncClient() as client:
                await client.post(f"{self.server_url}/message", json={
                    "sender": self.username,
                    "receiver": peer,
                    "header": packet["header"],
                    "ciphertext_hex": packet["ciphertext_hex"],
                    "signature": packet["signature"]
                })

    async def close(self):
        if self.ws:
            await self.ws.close()
