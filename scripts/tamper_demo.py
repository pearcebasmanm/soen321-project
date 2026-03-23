"""Tamper Demo"""

import requests

from api.crypto import tamper_ciphertext, verify_and_decrypt

SERVER = "http://127.0.0.1:8000"
MSG_ID = "msg1"


def main():
    response = requests.get(f"{SERVER}/messages/{MSG_ID}", timeout=10)
    response.raise_for_status()

    package = response.json()
    bad_package = tamper_ciphertext(package)

    try:
        verify_and_decrypt(bad_package)
        print("Unexpected success: tampering was not detected.")
    except Exception as e:
        print("Tampering detected successfully.")
        print("Error:", type(e).__name__, str(e))


if __name__ == "__main__":
    main()
