"""Bob Script"""
import requests

from api.crypto import verify_and_decrypt

SERVER = "http://127.0.0.1:8000"
MSG_ID = "msg1"


def main():
    response = requests.get(f"{SERVER}/messages/{MSG_ID}", timeout=10)
    response.raise_for_status()

    package = response.json()
    plaintext = verify_and_decrypt(package)

    print("Bob downloaded package and decrypted it.")
    print("Recovered plaintext:")
    print(plaintext.decode("utf-8"))


if __name__ == "__main__":
    main()
