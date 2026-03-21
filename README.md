# SOEN 321 Project

A Python commandline encryption/decryption tool for the Information Systems Security final project

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
- When contributing use a formatter like ruff: https://docs.astral.sh/ruff/installation/

## Features

TODO: Add RSA, and others.

## Scenario
A secure project file/message exchange system between two users over an untrusted network.

## Main design choices
- Diffie-Hellman key exchange for session establishment
- RSA signatures for authentication and integrity
- SHA-256 for key derivation and message digesting
- A hash-based XOR stream for symmetric message encryption in the prototype

## Files
- `number_theory.py`: modular arithmetic helpers
- `rsa.py`: RSA key generation, signing, and verification
- `dh.py`: Diffie-Hellman key exchange helpers
- `secure_messaging.py`: authenticated session setup and secure messaging
- `demo.py`: end-to-end demonstration script

## Run
```bash
py demo.py
```
