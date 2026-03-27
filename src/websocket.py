import asyncio
import sys

from websockets.asyncio.server import serve
from websockets.sync.client import connect

import aes
import rsa
import dh

from secure_messaging import (
    FirstPassMessage,
    LocalParty,
    RemoteParty,
    SecondPassMessage,
    initiate_session,
    respond_session,
    finalize_session,
)


async def aes_listen(websocket):
    # Generate rsa keys
    receiver = LocalParty(name="reveiver", rsa_keys=rsa.generate_keypair(bits=512))
    receiver_public = RemoteParty(receiver.name, receiver.rsa_keys.public)

    # Receive their public keys
    sender_public = RemoteParty.from_json(await websocket.recv())

    # Send our public keys
    await websocket.send(receiver_public.to_json())

    # Receive the Diffie-Hellman public keys
    params = dh.DHParameters.from_json(await websocket.recv())

    # Receive Diffie-Hellman first pass, and send the second pass
    message_1 = FirstPassMessage.from_json(await websocket.recv())
    message_2, user2_private_dh, user2_state = respond_session(
        receiver, sender_public, params, message_1
    )
    await websocket.send(message_2.to_json())

    # "Generate" the aes key from the session key
    session_key = user2_state.session_key
    aes_key = aes.AESKey(session_key[: aes.BLOCK_SIZE])

    ciphertext = await websocket.recv()

    message = aes.decrypt_text(ciphertext, aes_key)
    print(f"Received AES encrypted message: {message}")


def aes_send(dest: str, message: str):
    with connect(f"ws://{dest}:8765") as websocket:
        # Generate rsa keys and send our public keys
        sender = LocalParty(name="sender", rsa_keys=rsa.generate_keypair(bits=512))
        sender_public = RemoteParty(sender.name, sender.rsa_keys.public)
        # TODO: see if this can be authenticated
        websocket.send(sender_public.to_json())

        # Receive their public keys
        receiver_public = RemoteParty.from_json(websocket.recv())

        # Generate and send the Diffie-Hellman public keys
        params = dh.DHParameters()
        websocket.send(params.to_json())

        # Generate and send the first pass of Diffie-Hellman
        message_1, user1_private_dh = initiate_session(sender, receiver_public, params)
        websocket.send(message_1.to_json())

        # Receive Diffie-Hellman second pass
        message_2 = SecondPassMessage.from_json(websocket.recv())
        user1_state = finalize_session(
            sender, receiver_public, params, user1_private_dh, message_2
        )

        # "Generate" the aes key from the session key
        session_key = user1_state.session_key
        aes_key = aes.AESKey(session_key[: aes.BLOCK_SIZE])

        # Encrypt and send our actual message
        ciphertext = aes.encrypt_text(message, aes_key)
        websocket.send(ciphertext)


async def main():
    if len(sys.argv) > 2:
        aes_send(sys.argv[1], sys.argv[2])
    else:
        async with serve(aes_listen, "", 8765) as server:
            await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
