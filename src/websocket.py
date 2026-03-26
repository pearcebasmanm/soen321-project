import asyncio
import sys

from websockets.asyncio.server import serve
from websockets.sync.client import connect


async def echo(websocket):
    async for message in websocket:
        await websocket.send(message)


async def main():
    if len(sys.argv) > 1:
        with connect("ws://localhost:8765") as websocket:
            websocket.send("Hello World!")
            message = websocket.recv()
            print(f"Got: {message}")
    else:
        async with serve(echo, "localhost", 8765) as server:
            await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
