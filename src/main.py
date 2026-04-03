"""Secure Messaging Command Line Interface — SOEN 321 Course Project

Commands:
  demo      Run the complete end-to-end demonstration
  keygen    Generate an RSA key pair and save it to a JSON file
  exchange  Perform a Diffie-Hellman key exchange and save the session state
  encrypt   Encrypt and sign a message
  decrypt   Verify the sender's signature and decrypt a message

Step-by-step usage:
    python main.py keygen   --name User1 --out user1.json
    python main.py keygen   --name User2 --out user2.json
    python main.py exchange --user1 user1.json --user2 user2.json --out session.json
    python main.py encrypt  --session session.json --sender User1 \\
                            --sender-key user1.json --message "Hello User2!" --out packet.json
    python main.py decrypt  --session session.json --sender-key user1.json --packet packet.json
"""

import json
import sys
from pathlib import Path

import click

from dh import DHParameters
from rsa import RSAKeyPair, generate_keypair
from secure_messaging import (
    LocalParty,
    RemoteParty,
    SessionState,
    initiate_session,
    respond_session,
    finalize_session,
    encrypt_message,
    decrypt_message,
    packet_digest,
)


# This method reads and parse a JSON file; print an error message on failure.
def _load_json(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        click.echo(f"Error: file not found: {path}", err=True)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        click.echo(f"Error: invalid JSON in {path}: {exc}", err=True)
        sys.exit(1)


# This method serializes a dict to a JSON file.
def _save_json(path: str, data: dict) -> None:
    Path(path).write_text(json.dumps(data, indent=2))


# CLI group
@click.group()
def cli():
    """Secure Messaging System — SOEN 321 Course Project

    \b
    Quick start:
        python main.py demo

    \b
    Step-by-step usage:
        python main.py keygen   --name User1 --out user1.json
        python main.py keygen   --name User2 --out user2.json
        python main.py exchange --user1 user1.json --user2 user2.json --out session.json
        python main.py encrypt  --session session.json --sender User1 \\
                                --sender-key user1.json --message "Hello User2!" --out packet.json
        python main.py decrypt  --session session.json --sender-key user1.json --packet packet.json
    """


# This method generates an RSA key pair and save it to a file.
@cli.command()
@click.option("--name", required=True, help="Name to associate with this key pair.")
@click.option("--out", required=True, help="Output JSON file path.")
@click.option(
    "--bits", default=512, show_default=True, help="RSA modulus size in bits."
)
def keygen(name, out, bits):
    click.echo(f"Generating {bits}-bit RSA key pair for '{name}'...")
    kp = generate_keypair(bits=bits)
    _save_json(out, {"name": name, **kp.to_dict()})
    click.echo(f"  Public exponent (e) : {kp.public.e}")
    click.echo(f"  Modulus bit-length  : {kp.public.n.bit_length()}")
    click.echo(f"  Saved to            : {out}")


# This method performs a Diffie-Hellman key exchange and save the session state.
@cli.command()
@click.option("--user1", "user1_path", required=True, help="User1's key file (JSON).")
@click.option("--user2", "user2_path", required=True, help="User2's key file (JSON).")
@click.option("--out", required=True, help="Output session file path (JSON).")
def exchange(user1_path, user2_path, out):
    user1 = LocalParty.from_dict(_load_json(user1_path))
    user1_remote = RemoteParty(user1.name, user1.rsa_keys.public)
    user2 = LocalParty.from_dict(_load_json(user2_path))
    user2_remote = RemoteParty(user2.name, user2.rsa_keys.public)
    params = DHParameters()

    click.echo(f"DH prime bit-length : {params.p.bit_length()}  (2^127 - 1)")

    # Step 1: User1 sends signed DH public value A = g^a mod p
    click.echo(
        f"\n[1] {user1.name} sends signed DH public value A = g^a mod p, and signs it with RSA."
    )
    msg1, user1_priv = initiate_session(user1, user2_remote, params)
    click.echo(f"    A (first 40 digits): {str(msg1.public_value)[:40]}...")

    # Step 2: User2 verifies User1's signature, computes B and shared secret
    click.echo(f"\n[2] {user2.name} verifies {user1.name}'s RSA signature")
    click.echo(
        f"    {user2.name} generates private exponent b, computes B = g^b mod p, signs B with RSA"
    )
    try:
        msg2, _, user2_state = respond_session(user2, user1_remote, params, msg1)
    except ValueError:
        click.echo(f"    FAILED — {ValueError}", err=True)
        sys.exit(1)
    click.echo(f"    B (first 40 digits): {str(msg2.public_value)[:40]}...")
    click.echo(
        f"    Shared secret (first 10 hex): {hex(user2_state.shared_secret)[:12]}..."
    )

    # Step 3： User1 verifies User2's signature and derives the session key
    click.echo(
        f"\n[3] {user1.name} verifies {user2.name}'s RSA signature and derives session key"
    )
    try:
        user1_state = finalize_session(user1, user2_remote, params, user1_priv, msg2)
    except ValueError:
        click.echo(f"    FAILED — {ValueError}", err=True)
        sys.exit(1)

    click.echo(
        f"    Shared secrets match : {user1_state.shared_secret == user2_state.shared_secret}"
    )
    click.echo(
        f"    Shared secret (first 10 hex) : {user1_state.session_key.hex()[:12]}..."
    )

    _save_json(out, user1_state.to_dict())
    click.echo(f"\nSession saved to: {out}")


# This method encrypts and sign a plaintext message.
@cli.command()
@click.option(
    "--session",
    "session_path",
    required=True,
    help="Session file (JSON) produced by 'exchange'.",
)
@click.option("--sender", required=True, help="Name of the sender.")
@click.option(
    "--sender-key", "sender_key_path", required=True, help="Sender's key file (JSON)."
)
@click.option("--message", required=True, help="Plaintext message to encrypt.")
@click.option("--out", required=True, help="Output packet file path (JSON).")
def encrypt(session_path, sender, sender_key_path, message, out):
    session = SessionState.from_dict(_load_json(session_path))
    party = LocalParty.from_dict(_load_json(sender_key_path))

    if party.name != sender:
        click.echo(
            f"Warning: key file name '{party.name}' does not match --sender '{sender}'",
            err=True,
        )

    packet = encrypt_message(party, session, message)
    digest = packet_digest(packet)

    click.echo(f"Sender    : {sender}")
    click.echo(f"Plaintext : {message}")
    click.echo(f"Ciphertext (hex, first 48 chars) : {packet['ciphertext_hex'][:48]}...")
    click.echo(f"Packet digest (SHA-256)          : {digest}")
    _save_json(out, packet)
    click.echo(f"Saved to  : {out}")


# This method verifies the sender's RSA signature and decrypts a message.
@cli.command()
@click.option(
    "--session",
    "session_path",
    required=True,
    help="Session file (JSON) produced by 'exchange'.",
)
@click.option(
    "--sender-key",
    "sender_key_path",
    required=True,
    help="Sender's key file (JSON) for signature verification.",
)
@click.option(
    "--packet",
    "packet_path",
    required=True,
    help="Encrypted packet file (JSON) from 'encrypt'.",
)
def decrypt(session_path, sender_key_path, packet_path):
    session = SessionState.from_dict(_load_json(session_path))
    sender_data = _load_json(sender_key_path)
    packet = _load_json(packet_path)

    sender_pub = RSAKeyPair.from_dict(sender_data).public

    click.echo(f"Claimed sender : {packet['header']['sender']}")
    click.echo(f"Verifying RSA signature with {sender_data['name']}'s public key...")

    try:
        plaintext = decrypt_message(sender_pub, session, packet)
    except ValueError:
        click.echo(f"FAILED — {ValueError}", err=True)
        sys.exit(1)

    click.echo("Signature valid : True")
    click.echo(f"Plaintext       : {plaintext}")


# This method is used for the automation of the entire demo.
@cli.command()
@click.option("--bits", default=512, show_default=True, help="RSA key size in bits.")
def demo(bits):
    click.echo("  Secure Messaging System")

    # Step 1: key generation
    click.echo(f"\n[Step 1] Generating {bits}-bit RSA key pairs for User1 and User2")
    user1 = LocalParty(name="User1", rsa_keys=generate_keypair(bits=bits))
    user1_remote = RemoteParty(user1.name, user1.rsa_keys.public)
    user2 = LocalParty(name="User2", rsa_keys=generate_keypair(bits=bits))
    user2_remote = RemoteParty(user2.name, user2.rsa_keys.public)
    params = DHParameters()
    click.echo(f"  User1's modulus : {user1.rsa_keys.public.n.bit_length()} bits")
    click.echo(f"  User2's modulus : {user2.rsa_keys.public.n.bit_length()} bits")
    click.echo(f"  DH prime        : {params.p.bit_length()} bits")

    # Step 2: User1 initiates DH
    click.echo("\n[Step 2] User1 initiates Diffie-Hellman key exchange")
    click.echo("  User1 computes A = g^a mod p and signs A with the RSA private key")
    msg1, user1_priv = initiate_session(user1, user2_remote, params)
    click.echo(f"  A (first 40 digits) : {str(msg1.public_value)[:40]}...")

    # Step 3: User2 verifies and responds
    click.echo("\n[Step 3] User2 verifies User1's RSA signature.")
    click.echo("  User2 computes B = g^b mod p, derives the shared secret, signs B")
    msg2, _, user2_state = respond_session(user2, user1_remote, params, msg1)
    click.echo(f"  B (first 40 digits) : {str(msg2.public_value)[:40]}...")

    # Step 4: User1 finalizes
    click.echo(
        "\n[Step 4] User1 verifies User2's RSA signature and derives session key"
    )
    user1_state = finalize_session(user1, user2_remote, params, user1_priv, msg2)
    click.echo(
        f"  Shared secrets match : {user1_state.shared_secret == user2_state.shared_secret}"
    )
    click.echo(f"  Session key (first 8 hex) : {user1_state.session_key.hex()[:8]}...")

    # Step 5: Encrypt
    plaintext = "Hello User2, this message is confidential!"
    click.echo("\n[Step 5] User1 encrypts and signs a message")
    click.echo(f"  Plaintext  : {plaintext}")
    packet = encrypt_message(user1, user1_state, plaintext)
    click.echo(f"  Ciphertext : {packet['ciphertext_hex'][:48]}...")
    click.echo(f"  Digest     : {packet_digest(packet)}")

    # Step 6: Decrypt
    click.echo("\n[Step 6] User2 verifies User1's RSA signature and decrypts")
    recovered = decrypt_message(user1.rsa_keys.public, user2_state, packet)
    click.echo("  Signature valid : True")
    click.echo(f"  Plaintext       : {recovered}")
    click.echo("  Demo complete.")


if __name__ == "__main__":
    cli()
