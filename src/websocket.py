import asyncio
import sys

from websockets.asyncio.server import serve
from websockets.sync.client import connect

import aes


async def aes_listen(websocket):
    # while True:
    # INCREDIBLY INSECURE, ONLY FOR PROTOTYPING
    key_bytes = await websocket.recv()

    ciphertext = await websocket.recv()

    message = aes.decrypt_text(ciphertext, aes.AESKey(key_bytes))
    print(f"Received AES encrypted message: {message}")

    # async for message in websocket:
    #     await websocket.send(message)


def aes_send(dest: str, message: str):
    with connect(f"ws://{dest}:8765") as websocket:
        key = aes.generate_key()
        ciphertext = aes.encrypt_text(message, key)
        websocket.send(key.key_bytes)
        websocket.send(ciphertext)


async def main():
    if len(sys.argv) > 2:
        aes_send(sys.argv[1], sys.argv[2])
    else:
        async with serve(aes_listen, "", 8765) as server:
            await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
