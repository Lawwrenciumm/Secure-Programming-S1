import asyncio
import websockets
import json

# Store connected clients with their public keys
connected_clients = []

# Server handler that processes incoming connections
async def hello_handler(websocket, path):
    try:
        while True:  # Keep the WebSocket open for more messages
            # Await a message from the client
            message = await websocket.recv()
            print(f"Received message from client: {message}")
            
            # Parse the received message
            data = json.loads(message)
            
            if data["type"] == "hello":
                # Extract client fingerprint and add to client list
                client_id = websocket.remote_address  # Use remote address as client ID
                public_key = data["fingerprint"]
                
                # Add the client to the connected clients list if not already present
                if not any(client["client-id"] == client_id for client in connected_clients):
                    connected_clients.append({
                        "client-id": client_id,
                        "public-key": public_key
                    })
                    print(f"Client added: {client_id}")
                
                # Respond to the hello message
                response = {"type": "ack", "message": "Hello received, connection established!"}
                await websocket.send(json.dumps(response))
                print(f"Sent response: {response}")
            
            elif data["type"] == "client_list_request":
                # Send the list of connected clients
                response = {
                    "type": "client_list",
                    "servers": [
                        {
                            "address": websocket.local_address,  # Server's address
                            "server-id": "server-1",  # Unique server ID
                            "clients": connected_clients
                        }
                    ]
                }
                await websocket.send(json.dumps(response))
                print(f"Sent client list: {response}")
    
    except websockets.ConnectionClosed:
        print(f"Client disconnected: {websocket.remote_address}")
        # Remove the client from the list if they disconnect
        connected_clients[:] = [client for client in connected_clients if client["client-id"] != websocket.remote_address]

# Start the WebSocket server
async def start_server():
    server = await websockets.serve(hello_handler, "localhost", 8080)
    print("WebSocket server started on ws://localhost:8080")
    await server.wait_closed()

# Run the server
asyncio.get_event_loop().run_until_complete(start_server())
asyncio.get_event_loop().run_forever()
