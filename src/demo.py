from __future__ import annotations

from dh import DHParameters
from rsa import generate_keypair
from secure_messaging import (
    Party,
    initiate_session,
    respond_session,
    finalize_session,
    encrypt_message,
    decrypt_message,
    packet_digest,
)


def main() -> None:

    alice = Party(name="Alice", rsa_keys=generate_keypair(bits=512))
    bob = Party(name="Bob", rsa_keys=generate_keypair(bits=512))
    params = DHParameters()
    plaintext = ("I have a crush on my professor, but I don't know how to tell her. I hope she doesn't find out.")

    print("1) RSA keys generated for Alice and Bob.")
    print(f"   Alice modulus bit-length: {alice.rsa_keys.public.n.bit_length()}")
    print(f"   Bob modulus bit-length:   {bob.rsa_keys.public.n.bit_length()}")
    print(f"   DH prime bit-length:      {params.p.bit_length()}")

    message_1, alice_private_dh = initiate_session(alice, bob, params)
    print("\n2) Alice sends signed DH value A = g^a mod p")
    print(f"   A = {message_1['public_value']}")

    message_2, bob_private_dh, bob_state = respond_session(bob, alice, params, message_1)
    print("\n3) Bob verifies Alice's signature, sends signed DH value B = g^b mod p")
    print(f"   B = {message_2['public_value']}")

    alice_state = finalize_session(alice, bob, params, alice_private_dh, message_2)
    print("\n4) Alice verifies Bob's signature and computes the shared secret.")
    print(f"   Alice shared secret: {alice_state.shared_secret}")
    print(f"   Bob shared secret:   {bob_state.shared_secret}")
    print(f"   Shared secrets match: {alice_state.shared_secret == bob_state.shared_secret}")

    packet = encrypt_message(alice, alice_state, plaintext)
    print("\n5) Alice encrypts and signs a message.")
    print(f"   Packet digest: {packet_digest(packet)}")
    print(f"   Ciphertext (hex, first 64 chars): {packet['ciphertext_hex'][:64]}...")

    recovered = decrypt_message(alice.rsa_keys.public, bob_state, packet)
    print("\n6) Bob verifies the signature and decrypts the message.")
    print(f"   Recovered plaintext: {recovered}")

    print("\nDemo complete.")


if __name__ == "__main__":
    main()
