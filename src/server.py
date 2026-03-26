from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import json
import asyncio
from dataclasses import dataclass, field
from collections import defaultdict

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserRegistration(BaseModel):
    username: str
    public_key_n: int
    public_key_e: int

class SessionInitiate(BaseModel):
    sender: str
    receiver: str
    public_value: int
    nonce_a: str
    signature: int

class SessionResponse(BaseModel):
    sender: str
    receiver: str
    public_value: int
    nonce_a: str
    nonce_b: str
    signature: int

class EncryptedMessage(BaseModel):
    sender: str
    receiver: str
    header: dict
    ciphertext_hex: str
    signature: int

@dataclass
class User:
    username: str
    public_key_n: int
    public_key_e: int
    websocket: Optional[WebSocket] = None

@dataclass
class PendingSession:
    initiator: str
    responder: str
    message_1: dict
    message_2: Optional[dict] = None
    finalized: bool = False

class ConnectionManager:
    def __init__(self):
        self.users: dict[str, User] = {}
        self.pending_sessions: dict[str, PendingSession] = {}
        self.active_connections: dict[str, WebSocket] = {}
        self.message_queues: dict[str, list] = defaultdict(list)

    async def register_user(self, username: str, public_key_n: int, public_key_e: int):
        self.users[username] = User(
            username=username,
            public_key_n=public_key_n,
            public_key_e=public_key_e
        )

    def get_user(self, username: str) -> Optional[User]:
        return self.users.get(username)

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[username] = websocket
        if username in self.users:
            self.users[username].websocket = websocket

    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]
        if username in self.users:
            self.users[username].websocket = None

    async def send_to_user(self, username: str, message: dict):
        if username in self.active_connections:
            await self.active_connections[username].send_json(message)
        else:
            self.message_queues[username].append(message)

    def get_pending_messages(self, username: str) -> list:
        messages = self.message_queues[username]
        self.message_queues[username] = []
        return messages

manager = ConnectionManager()

@app.post("/register")
async def register(data: UserRegistration):
    if data.username in manager.users:
        raise HTTPException(status_code=400, detail="Username already taken")
    await manager.register_user(data.username, data.public_key_n, data.public_key_e)
    return {"status": "registered", "username": data.username}

@app.get("/users")
async def list_users():
    return {
        "users": [
            {
                "username": u.username,
                "public_key_n": u.public_key_n,
                "public_key_e": u.public_key_e,
                "online": u.username in manager.active_connections
            }
            for u in manager.users.values()
        ]
    }

@app.get("/user/{username}")
async def get_user(username: str):
    user = manager.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": user.username,
        "public_key_n": user.public_key_n,
        "public_key_e": user.public_key_e,
        "online": username in manager.active_connections
    }

@app.post("/session/initiate")
async def initiate_session(data: SessionInitiate):
    if data.sender not in manager.users:
        raise HTTPException(status_code=400, detail="Sender not registered")
    if data.receiver not in manager.users:
        raise HTTPException(status_code=400, detail="Receiver not registered")
    
    session_id = f"{data.sender}:{data.receiver}"
    message_1 = {
        "sender": data.sender,
        "receiver": data.receiver,
        "public_value": data.public_value,
        "nonce_a": data.nonce_a,
        "signature": data.signature
    }
    
    manager.pending_sessions[session_id] = PendingSession(
        initiator=data.sender,
        responder=data.receiver,
        message_1=message_1
    )
    
    await manager.send_to_user(data.receiver, {
        "type": "session_request",
        "session_id": session_id,
        "message_1": message_1
    })
    
    return {"status": "initiated", "session_id": session_id}

@app.post("/session/{session_id}/respond")
async def respond_session(session_id: str, data: SessionResponse):
    if session_id not in manager.pending_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = manager.pending_sessions[session_id]
    message_2 = {
        "sender": data.sender,
        "receiver": data.receiver,
        "public_value": data.public_value,
        "nonce_a": data.nonce_a,
        "nonce_b": data.nonce_b,
        "signature": data.signature
    }
    
    session.message_2 = message_2
    
    await manager.send_to_user(session.initiator, {
        "type": "session_response",
        "session_id": session_id,
        "message_2": message_2
    })
    
    return {"status": "responded", "session_id": session_id}

@app.post("/session/{session_id}/finalize")
async def finalize_session(session_id: str):
    if session_id not in manager.pending_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = manager.pending_sessions[session_id]
    session.finalized = True
    
    await manager.send_to_user(session.responder, {
        "type": "session_finalized",
        "session_id": session_id
    })
    
    return {"status": "finalized", "session_id": session_id}

@app.post("/message")
async def send_message(data: EncryptedMessage):
    packet = {
        "type": "encrypted_message",
        "sender": data.sender,
        "header": data.header,
        "ciphertext_hex": data.ciphertext_hex,
        "signature": data.signature
    }
    
    await manager.send_to_user(data.receiver, packet)
    
    return {"status": "sent"}

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    if username not in manager.users:
        await websocket.close(code=4001)
        return
    
    await manager.connect(websocket, username)
    
    pending = manager.get_pending_messages(username)
    for msg in pending:
        await websocket.send_json(msg)
    
    try:
        while True:
            data = await websocket.receive_json()
            
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            
            elif data.get("type") == "message":
                receiver = data.get("receiver")
                if receiver:
                    await manager.send_to_user(receiver, {
                        "type": "encrypted_message",
                        "sender": username,
                        "header": data.get("header"),
                        "ciphertext_hex": data.get("ciphertext_hex"),
                        "signature": data.get("signature")
                    })
    
    except WebSocketDisconnect:
        manager.disconnect(username)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
