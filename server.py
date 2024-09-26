import json
import asyncio
import websockets

# Global Variables
connected_clients = []      # List of connected clients
server_connections = {}     # Dictionary of connected servers
server_id = None            # Unique identifier for this server

# Broadcast a message to all connected clients
async def broadcast_to_clients(message):
    if connected_clients:
        await asyncio.gather(
            *[client['websocket'].send(json.dumps(message)) for client in connected_clients],
            return_exceptions=True
        )

# Forward a message to all connected servers except the sender
async def forward_to_servers(message, exclude_server=None):
    for sid, conn_info in server_connections.items():
        if sid == exclude_server:
            continue  # Skip the server we received the message from
        websocket = conn_info['websocket']
        try:
            await websocket.send(json.dumps(message))
        except websockets.ConnectionClosed:
            print(f"Connection to server {sid} lost.")
            # Handle reconnection
            await handle_server_disconnection(sid)
        except Exception as e:
            print(f"Error sending message to server {sid}: {e}")

# Handle messages from clients
async def handle_client_messages(websocket, client_id):
    try:
        async for message in websocket:
            data = json.loads(message)
            if data['type'] == 'public_chat':
                # Add origin server ID to the message
                data['origin_server'] = server_id
                # Broadcast to local clients
                await broadcast_to_clients(data)
                # Forward to other servers
                await forward_to_servers(data)
            else:
                print(f"Unknown message type from client {client_id}: {data['type']}")
    except websockets.ConnectionClosed:
        print(f"Client {client_id} disconnected.")
        # Remove client from connected_clients
        connected_clients[:] = [c for c in connected_clients if c['client_id'] != client_id]

# Handle messages from servers
async def handle_server_messages(websocket, sid):
    try:
        async for message in websocket:
            data = json.loads(message)
            if data['type'] == 'public_chat':
                if data.get('origin_server') == server_id:
                    # Ignore messages originating from this server
                    continue
                # Broadcast to local clients
                await broadcast_to_clients(data)
                # Forward to other servers excluding the sender
                await forward_to_servers(data, exclude_server=sid)
            else:
                print(f"Unknown message type from server {sid}: {data['type']}")
    except websockets.ConnectionClosed:
        print(f"Server {sid} disconnected.")
        await handle_server_disconnection(sid)

# Handle disconnection of a server
async def handle_server_disconnection(sid):
    if sid in server_connections:
        uri = server_connections[sid]['uri']
        del server_connections[sid]
        # Attempt to reconnect
        asyncio.create_task(reconnect_to_server(uri, sid))

# Reconnect to a server
async def reconnect_to_server(uri, sid):
    while True:
        try:
            print(f"Attempting to reconnect to server {sid} at {uri}")
            websocket = await websockets.connect(uri)
            # Perform handshake
            await websocket.send(json.dumps({'type': 'server_hello', 'server_id': server_id}))
            response = await websocket.recv()
            data = json.loads(response)
            if data['type'] == 'server_hello':
                if data['server_id'] != sid:
                    print(f"Server ID mismatch. Expected {sid}, got {data['server_id']}")
                    await websocket.close()
                    continue
                server_connections[sid] = {'websocket': websocket, 'uri': uri}
                print(f"Reconnected to server {sid} at {uri}")
                # Start handling messages
                asyncio.create_task(handle_server_messages(websocket, sid))
                break
            else:
                print(f"Invalid handshake response from server {sid}")
                await websocket.close()
        except Exception as e:
            print(f"Failed to reconnect to server {sid}: {e}")
            await asyncio.sleep(5)  # Wait before retrying

# Accept incoming connections
async def accept_connection(websocket, path):
    try:
        # Expect an initial message to determine the connection type
        message = await websocket.recv()
        data = json.loads(message)
        if data['type'] == 'hello':
            # Client connection
            client_id = data['fingerprint']
            connected_clients.append({'client_id': client_id, 'websocket': websocket})
            print(f"Client {client_id} connected.")
            # Send acknowledgment
            await websocket.send(json.dumps({'type': 'ack', 'message': 'Connected to server'}))
            # Start handling client messages
            await handle_client_messages(websocket, client_id)
        elif data['type'] == 'server_hello':
            # Server connection
            sid = data['server_id']
            # Send back our server_hello
            await websocket.send(json.dumps({'type': 'server_hello', 'server_id': server_id}))
            server_connections[sid] = {'websocket': websocket, 'uri': None}
            print(f"Server {sid} connected.")
            # Start handling server messages
            await handle_server_messages(websocket, sid)
        else:
            print(f"Unknown connection type: {data['type']}")
            await websocket.close()
    except websockets.ConnectionClosed:
        print("Connection closed before handshake.")
    except Exception as e:
        print(f"Error during connection: {e}")
        await websocket.close()

# Connect to other servers
async def connect_to_other_servers(server_list):
    for uri in server_list:
        asyncio.create_task(connect_to_server(uri))

# Connect to a server
async def connect_to_server(uri):
    while True:
        try:
            print(f"Connecting to server at {uri}")
            websocket = await websockets.connect(uri)
            # Send server_hello
            await websocket.send(json.dumps({'type': 'server_hello', 'server_id': server_id}))
            # Receive server_hello
            response = await websocket.recv()
            data = json.loads(response)
            if data['type'] == 'server_hello':
                sid = data['server_id']
                server_connections[sid] = {'websocket': websocket, 'uri': uri}
                print(f"Connected to server {sid} at {uri}")
                # Start handling server messages
                asyncio.create_task(handle_server_messages(websocket, sid))
                break
            else:
                print(f"Invalid handshake response from server at {uri}")
                await websocket.close()
        except Exception as e:
            print(f"Failed to connect to server at {uri}: {e}")
            await asyncio.sleep(5)  # Wait before retrying

# Main function to start the server
async def start_server():
    global server_id
    # Get server details from the user
    host_port = input("Server Port: ")
    server_id = input("Server ID: ")
    neighbour_servers = input("Server Connections (space-separated URIs): ")

    # Parse neighbour server URIs
    server_list = neighbour_servers.strip().split()
    server_list = ["ws://localhost:" + port for port in server_list]

    # Start the server to accept incoming connections
    server = await websockets.serve(accept_connection, 'localhost', int(host_port))
    print(f"Server {server_id} started on port {host_port}")

    # Connect to other servers
    asyncio.create_task(connect_to_other_servers(server_list))

    # Keep the server running
    await asyncio.Future()  # Run forever

# Entry point
if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("Server shutting down.")
