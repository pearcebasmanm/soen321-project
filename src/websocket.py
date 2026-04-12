"""
WebSocket transport layer for real-time secure messaging.
"""
import asyncio
import json

from websockets.asyncio.server import serve
from websockets.sync.client import connect

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
    encrypt_message,
    decrypt_message,
)


async def message_receive(websocket):
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
    message_2, _, user2_state = respond_session(
        receiver, sender_public, params, message_1
    )
    await websocket.send(message_2.to_json())

    packet = json.loads(await websocket.recv())
    message = decrypt_message(sender_public, user2_state, packet)
    print(f"Received message: {message}")


def message_send(dest: str, message: str, port: int):
    with connect(f"ws://{dest}:{port}") as websocket:
        # Generate rsa keys and send our public keys
        sender = LocalParty(name="sender", rsa_keys=rsa.generate_keypair(bits=512))
        sender_public = RemoteParty(sender.name, sender.rsa_keys.public)
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

        # Encrypt, sign, and send the message
        packet = encrypt_message(sender, user1_state, message)
        websocket.send(json.dumps(packet))


def listener_thread(port):
    async def _serve_listener(port):
        async with serve(message_receive, "", port) as server:
            await server.serve_forever()

    asyncio.run(_serve_listener(port))
