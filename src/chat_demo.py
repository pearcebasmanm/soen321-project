import asyncio
import sys
from client import SecureClient

SERVER_URL = "http://localhost:8000"

async def run_client(username: str):
    client = SecureClient(SERVER_URL, username)
    
    print(f"[{username}] Registering...")
    await client.register()
    print(f"[{username}] Registered with RSA keys")
    
    await client.connect_websocket()
    print(f"[{username}] Connected to server")
    
    async def on_message(sender: str, plaintext: str):
        print(f"\n[{username}] Message from {sender}: {plaintext}")
        print(f"[{username}] > ", end="", flush=True)
    
    async def on_session(event_type: str, data: dict):
        if event_type == "request":
            session_id = data["session_id"]
            message_1 = data["message_1"]
            peer = message_1["sender"]
            print(f"\n[{username}] Session request from {peer}")
            await client.respond_to_session(session_id, message_1)
            print(f"[{username}] Session established with {peer}")
            print(f"[{username}] > ", end="", flush=True)
        elif event_type == "established":
            print(f"\n[{username}] Session established with {data['peer']}")
            print(f"[{username}] > ", end="", flush=True)
    
    client.message_handler = on_message
    client.session_handler = on_session
    
    print(f"\n[{username}] Commands:")
    print(f"  /users - List online users")
    print(f"  /connect <user> - Start secure session")
    print(f"  /msg <user> <message> - Send encrypted message")
    print(f"  /quit - Exit")
    print()
    
    while True:
        try:
            print(f"[{username}] > ", end="", flush=True)
            line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
            line = line.strip()
            
            if not line:
                continue
            
            if line == "/users":
                users = await client.list_users()
                print(f"[{username}] Online users:")
                for u in users:
                    status = "online" if u["online"] else "offline"
                    print(f"  - {u['username']} ({status})")
            
            elif line.startswith("/connect "):
                peer = line.split(" ", 1)[1]
                print(f"[{username}] Initiating session with {peer}...")
                await client.initiate_session(peer)
            
            elif line.startswith("/msg "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print(f"[{username}] Usage: /msg <user> <message>")
                    continue
                peer = parts[1]
                message = parts[2]
                await client.send_message(peer, message)
                print(f"[{username}] Sent encrypted message to {peer}")
            
            elif line == "/quit":
                break
            
            else:
                print(f"[{username}] Unknown command. Use /users, /connect, /msg, or /quit")
        
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[{username}] Error: {e}")
    
    await client.close()
    print(f"[{username}] Disconnected")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python chat_demo.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    asyncio.run(run_client(username))
