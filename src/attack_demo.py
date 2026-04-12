"""
Attack scenario demonstrations with three test cases:
1. MITM on DH handshake;
2. Tampered packet;
3. Intra-session message replay.
"""

from dh import DHParameters
from rsa import generate_keypair
from secure_messaging import (
    LocalParty,
    RemoteParty,
    initiate_session,
    respond_session,
    finalize_session,
    encrypt_message,
    decrypt_message,
)


def _setup():
    """Prepare two parties and a completed message exchange session."""
    user1 = LocalParty(name="User1", rsa_keys=generate_keypair(bits=512))
    user2 = LocalParty(name="User2", rsa_keys=generate_keypair(bits=512))
    user1_remote = RemoteParty(user1.name, user1.rsa_keys.public)
    user2_remote = RemoteParty(user2.name, user2.rsa_keys.public)
    params = DHParameters()

    msg1, user1_priv = initiate_session(user1, user2_remote, params)
    msg2, _, user2_state = respond_session(user2, user1_remote, params, msg1)
    user1_state = finalize_session(user1, user2_remote, params, user1_priv, msg2)

    return user1, user2, user1_state, user2_state


def demo_mitm_on_dh_handshake():
    """
    An attacker changes the public value A of the first DH message.
    Because A is signed with User1's private key,
    the tampered value will not match and the handshake must fail.
    """
    print("Attack 1: MITM on DH Handshake")

    user1 = LocalParty(name="User1", rsa_keys=generate_keypair(bits=512))
    user2 = LocalParty(name="User2", rsa_keys=generate_keypair(bits=512))
    user1_remote = RemoteParty(user1.name, user1.rsa_keys.public)
    user2_remote = RemoteParty(user2.name, user2.rsa_keys.public)
    params = DHParameters()

    msg1, _ = initiate_session(user1, user2_remote, params)
    print(f"  Original DH public value A (last 20 digits): ...{str(msg1.public_value)[-20:]}")

    # Attacker replaces A with a different value
    msg1.public_value = msg1.public_value + 1
    print(f"  Tampered DH public value A (last 20 digits): ...{str(msg1.public_value)[-20:]}")

    try:
        respond_session(user2, user1_remote, params, msg1)
        print("  RESULT: FAIL: Tampered message was accepted.")
    except ValueError as e:
        print(f"  RESULT: Rejected: {e}")
    print()


def demo_tampered_ciphertext():
    """
    An attacker flips a byte in the ciphertext. 
    The receiver must refuse to decrypt the message.
    """
    print("Attack 2: Tampered Ciphertext")

    user1, user2, user1_state, user2_state = _setup()

    packet = encrypt_message(user1, user1_state, "Hello User2!")
    original_ciphertext = packet["ciphertext_hex"]
    print(f"  Original ciphertext (last 10 hex chars): ...{original_ciphertext[-10:]}")

    # Attacker flips the last byte of the ciphertext
    tampered_bytes = bytearray(bytes.fromhex(original_ciphertext))
    tampered_bytes[-1] ^= 0xFF
    packet["ciphertext_hex"] = tampered_bytes.hex()
    print(f"  Tampered ciphertext (last 10 hex chars): ...{packet['ciphertext_hex'][-10:]}")

    try:
        decrypt_message(RemoteParty(user1.name, user1.rsa_keys.public), user2_state, packet)
        print("  RESULT: FAIL: Tampered packet was accepted.")
    except ValueError as e:
        print(f"  RESULT: Rejected: {e}")
    print()


def demo_intra_session_replay():
    """
    An attacker re-sends a previous message within the same session. 
    The sequence number counter must detect the duplicate and reject the replayed packet.
    """
    print("Attack 3: Intra-Session Replay Attack")

    user1, user2, user1_state, user2_state = _setup()
    sender_public = RemoteParty(user1.name, user1.rsa_keys.public)

    packet = encrypt_message(user1, user1_state, "Hello User2!")

    # First decryption (should be accepted)
    plaintext = decrypt_message(sender_public, user2_state, packet)
    print(f"  First decryption (seq=0): '{plaintext}' — accepted")

    # Replay the same packet
    try:
        decrypt_message(sender_public, user2_state, packet)
        print("  RESULT: FAIL: Replayed packet was accepted.")
    except ValueError as e:
        print(f"  RESULT: Rejected: {e}")
    print()


if __name__ == "__main__":
    print("\nSOEN 321 — Attack Scenario Demonstrations\n")
    demo_mitm_on_dh_handshake()
    demo_tampered_ciphertext()
    demo_intra_session_replay()
    print("All attack scenarios completed.")
