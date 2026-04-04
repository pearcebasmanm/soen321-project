# SOEN 321 Project

A Python secure messaging system for the SOEN 321 final project. It implements authenticated key exchange signature mechanism and end-to-end encrypted communication over an untrusted network.

## Group

- Alex Khoury
- Christopher Murdoch Egener
- Hudson Lu
- Jeremy Anderson
- Max Pearce Basman
- Tianmu Yang

## Setup

- Install uv: https://docs.astral.sh/uv/getting-started/installation/
- Run `uv run src/main.py`

## Design Choices

- **Diffie-Hellman key exchange** establishes a shared session key.
- **RSA signatures** authenticates DH public values and signs every message packet to guarantee integrity.
- **AES-128** provides symmetric encryption of message content using the derived session key.
- **SHA-256** is used for session key derivation and RSA signature hashing.
- **Nonces** are 128-bit random values included in each session to prevent replay attacks.

## Modules

- `number_theory.py`: modular arithmetic primitives: extended GCD, Miller-Rabin primality test, prime generation
- `rsa.py`: RSA key pair generation, digital signatures, and verification
- `dh.py`: Diffie-Hellman parameters (RFC 3526 Group 14) and key exchange primitives
- `aes.py`: AES-128 with key expansion, encryption, decryption and PKCS7 padding
- `secure_messaging.py`: authenticated three-phase DH session establishment and AES-encrypted message exchange
- `main.py`: command-line interface for demo purposes
- `websocket.py`: provides real-time communication between two machines

## Usage

### Demo (single machine)

Runs the full protocol end-to-end in a single process.

```bash
python src/main.py demo
```

### Step-by-step CLI

```bash
# Generate RSA key pairs
python src/main.py keygen --name User1 --out user1.json
python src/main.py keygen --name User2 --out user2.json

# Perform authenticated Diffie-Hellman key exchange
python src/main.py exchange --user1 user1.json --user2 user2.json --out session.json

# Encrypt and sign a message
python src/main.py encrypt --session session.json --sender User1 \
                           --sender-key user1.json \
                           --message "Hello User2!" --out packet.json

# Verify signature and decrypt
python src/main.py decrypt --session session.json \
                           --sender-key user1.json --packet packet.json
```

### WebSocket (two machines)

```bash
# Machine A (receiver)
python src/websocket.py

# Machine B (sender)
python src/websocket.py <Machine-A-IP> "Hello!"
```
