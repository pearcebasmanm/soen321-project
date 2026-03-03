# SOEN 321 - Option 2 Prototype
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