"""Alice Script"""
from __future__ import annotations

import requests

from api.crypto import encrypt_and_sign

SERVER = "http://127.0.0.1:8000"
MSG_ID = "msg1"


def main():
    plaintext = b"Hello Bob. This is Alice sending a secure message through an untrusted server."

    package = encrypt_and_sign(plaintext)

    response = requests.post(
        f"{SERVER}/messages/{MSG_ID}",
        json=package,
        timeout=10,
    )
    response.raise_for_status()

    print("Alice uploaded encrypted package.")
    print(response.json())


if __name__ == "__main__":
    main()
