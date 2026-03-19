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

    user1 = Party(name="User1", rsa_keys=generate_keypair(bits=512))
    user2 = Party(name="User2", rsa_keys=generate_keypair(bits=512))
    params = DHParameters()
    plaintext = "I have a crush on my professor, but I don't know how to tell her. I hope she doesn't find out."

    print("1) RSA keys generated for User1 and User2.")
    print(f"   User1 modulus bit-length: {user1.rsa_keys.public.n.bit_length()}")
    print(f"   User2 modulus bit-length: {user2.rsa_keys.public.n.bit_length()}")
    print(f"   DH prime bit-length:      {params.p.bit_length()}")

    message_1, user1_private_dh = initiate_session(user1, user2, params)
    print("\n2) User1 sends signed DH value A = g^a mod p")
    print(f"   A = {message_1['public_value']}")

    message_2, user2_private_dh, user2_state = respond_session(
        user2, user1, params, message_1
    )
    print("\n3) User2 verifies User1's signature, sends signed DH value B = g^b mod p")
    print(f"   B = {message_2['public_value']}")

    user1_state = finalize_session(user1, user2, params, user1_private_dh, message_2)
    print("\n4) User1 verifies User2's signature and computes the shared secret.")
    print(f"   User1 shared secret: {user1_state.shared_secret}")
    print(f"   User2 shared secret: {user2_state.shared_secret}")
    print(
        f"   Shared secrets match: {user1_state.shared_secret == user2_state.shared_secret}"
    )

    packet = encrypt_message(user1, user1_state, plaintext)
    print("\n5) User1 encrypts and signs a message.")
    print(f"   Packet digest: {packet_digest(packet)}")
    print(f"   Ciphertext (hex, first 64 chars): {packet['ciphertext_hex'][:64]}...")

    recovered = decrypt_message(user1.rsa_keys.public, user2_state, packet)
    print("\n6) User2 verifies the signature and decrypts the message.")
    print(f"   Recovered plaintext: {recovered}")

    print("\nDemo complete.")


if __name__ == "__main__":
    main()
