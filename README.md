# SOEN 321 Project

A secure messaging system with end-to-end encryption for the Information Systems Security final project.

## Group

- Alex Khoury
- Christopher Murdoch Egener
- Hudson Lu
- Jeremy Anderson
- Max Pearce Basman
- Tianmu Yang

## Setup

- Install uv: https://docs.astral.sh/uv/getting-started/installation/
- Run `uv sync` to install dependencies
- When contributing use a formatter like ruff: https://docs.astral.sh/ruff/installation/

## Scenario
A secure project file/message exchange system between two users over an untrusted network.

## Main design choices
- Diffie-Hellman key exchange for session establishment
- RSA signatures for authentication and integrity
- SHA-256 for key derivation and message digesting
- A hash-based XOR stream for symmetric message encryption in the prototype
- FastAPI + WebSockets for real-time client-server communication

## Architecture

```
Client A  <--WebSocket-->  FastAPI Server  <--WebSocket-->  Client B
   |                            |                              |
   |  1. Register (RSA pubkey)  |                              |
   |--------------------------->|                              |
   |                            |  1. Register (RSA pubkey)    |
   |                            |<-----------------------------|
   |  2. Initiate session (DH)  |                              |
   |--------------------------->|  3. Forward session request  |
   |                            |----------------------------->|
   |                            |  4. Session response (DH)    |
   |  5. Forward response       |<-----------------------------|
   |<---------------------------|                              |
   |  6. Finalize session       |                              |
   |--------------------------->|  7. Notify finalized         |
   |                            |----------------------------->|
   |  8. Encrypted messages     |  8. Relay encrypted msgs     |
   |<-------------------------->|<---------------------------->|
```

## Files
- `number_theory.py`: modular arithmetic helpers
- `rsa.py`: RSA key generation, signing, and verification
- `dh.py`: Diffie-Hellman key exchange helpers
- `secure_messaging.py`: authenticated session setup and secure messaging
- `server.py`: FastAPI server with WebSocket support
- `client.py`: async client library for secure communication
- `chat_demo.py`: interactive chat demo
- `demo.py`: local end-to-end demonstration script

## Run Local Demo
```bash
uv run src/demo.py
```

## Run Networked Chat

Terminal 1 - Start server:
```bash
uv run src/server.py
```

Terminal 2 - Start client Alice:
```bash
uv run src/chat_demo.py alice
```

Terminal 3 - Start client Bob:
```bash
uv run src/chat_demo.py bob
```

In Alice's terminal:
```
/connect bob
/msg bob Hello from Alice!
```

In Bob's terminal (after accepting session):
```
/msg alice Hello back!
```

## Chat Commands
- `/users` - List registered users
- `/connect <user>` - Initiate secure session with user
- `/msg <user> <message>` - Send encrypted message
- `/quit` - Exit
