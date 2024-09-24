import json
import asyncio
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

connected_clients = []

# Broadcast a message to all connected clients
async def broadcast_message(message):
    if connected_clients:
        await asyncio.wait([client['websocket'].send(json.dumps(message)) for client in connected_clients])

# Handle each client's connection
async def hello_handler(websocket, path):
    try:
        async for message in websocket:
            data = json.loads(message)

            # Handle hello message
            if data["type"] == "hello":
                public_key = data["public-key"]
                client_id = data["fingerprint"]

                # Add the client to the connected clients list if not already present
                if not any(client["client-id"] == client_id for client in connected_clients):
                    connected_clients.append({
                        "client-id": client_id,
                        "public-key": public_key,
                        "websocket": websocket
                    })
                    print(f"Client added: {client_id}")

                # Respond to the hello message
                response = {"type": "ack", "message": "Hello received, connection established!"}
                await websocket.send(json.dumps(response))
                print(f"Sent response: {response}")

            # Handle public chat message
            elif data["type"] == "public_chat":
                chat_message = {
                    "type": "public_chat",
                    "from": data["from"],
                    "message": data["message"]
                }
                print(f"Public message from {data['from']}: {data['message']}")
                await broadcast_message(chat_message)

            # Handle client list request
            elif data["type"] == "client_list_request":
                # Send the list of connected clients
                response = {
                    "type": "client_list",
                    "servers": [
                        {
                            "address": websocket.local_address,
                            "server-id": "server-1",
                            "clients": [{"client-id": client["client-id"]} for client in connected_clients]
                        }
                    ]
                }
                await websocket.send(json.dumps(response))
                print(f"Sent client list: {response}")

    except websockets.ConnectionClosed:
        print(f"Client disconnected: {websocket.remote_address}")
        # Remove the client from the list if they disconnect
        connected_clients[:] = [client for client in connected_clients if client["websocket"] != websocket]

# Start the WebSocket server
async def start_server():
    server = await websockets.serve(hello_handler, "0.0.0.0", 23451)
    print("WebSocket server started on ws://0.0.0.0:23451")
    await server.wait_closed()

# Run the server
asyncio.get_event_loop().run_until_complete(start_server())
asyncio.get_event_loop().run_forever()