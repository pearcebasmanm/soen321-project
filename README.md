# SOEN 321 Project

A Python secure messaging system for the SOEN 321 final project. It implements authenticated key exchange signature mechanism and end-to-end encrypted communication over an untrusted network.

## Group

- Alex Khoury
- Christopher Murdoch Egener
- Hudson Lu
- Jeremy Anderson
- Max Pearce Basman
- Tianmu Yang

## Development Setup

- Install uv (manages packages and environment automatically): https://docs.astral.sh/uv/getting-started/installation/
- Install ruff (formatter, skip if just using application): https://docs.astral.sh/ruff/
- Invoke python files with `uv run src/filename.py` instead of `python src/filename.py`

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
- `websocket.py`: implements real-time communication infrastrure between two machines
- `app.py`: provides a live application interface between two users

## Usage

### Protocol Demo (single machine)

Runs the full protocol end-to-end in a single process.

```bash
uv run src/main.py demo
```

### Attack Demo (single machine)

Demonstrates three attack scenarios.

```bash
uv run src/attack_demo.py
```

### Step-by-step CLI

```bash
# Generate RSA key pairs
uv run src/main.py keygen --name User1 --out user1.json
uv run src/main.py keygen --name User2 --out user2.json

# Perform authenticated Diffie-Hellman key exchange
uv run src/main.py exchange --user1 user1.json --user2 user2.json --out session.json

# Encrypt and sign a message
uv run src/main.py encrypt --session session.json --sender User1 \
                           --sender-key user1.json \
                           --message "Hello User2!" --out packet.json

# Verify signature and decrypt
uv run src/main.py decrypt --session session.json \
                           --sender-key user1.json --packet packet.json
```

### WebSocket Application (two machines on same network)

```bash
# Machine A
uv run src/app.py --dest <Machine-B-IP>

# Machine B
uv run src/app.py --dest <Machine-A-IP>

# start sending messages on either machine
```

### WebSocket Application (one machine)

```bash
# Console A
uv run src/app.py --port 8001 --dest-port 8002

# Console B
uv run src/app.py --port 8002 --dest-port 8001

# start sending messages on either console
```
