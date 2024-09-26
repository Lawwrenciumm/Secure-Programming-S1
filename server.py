import json
import asyncio
import websockets

connected_clients = []
server_connections = {}  # Dictionary to track connections to other servers by their URI
server_id = 0

# Broadcast a message to all connected clients
async def broadcast_message_to_clients(message):
    if connected_clients:
        await asyncio.gather(*(client['websocket'].send(json.dumps(message)) for client in connected_clients))

async def forward_to_servers(message):
    global server_connections
    stale_connections = []

    # Iterate over active connections and forward the message
    for server_uri, server_ws in server_connections.items():
        try:
            await server_ws.send(json.dumps(message))
        except websockets.ConnectionClosedOK:
            print(f"Connection to server {server_uri} closed gracefully.")
            stale_connections.append(server_uri)  # Mark connection as stale
        except Exception as e:
            print(f"Error sending message to {server_uri}: {e}")
            stale_connections.append(server_uri)

    # Remove stale connections and attempt to reconnect
    for uri in stale_connections:
        del server_connections[uri]
        print(f"Removed stale connection to server {uri}")
        # Attempt to reconnect after removing the stale connection
        asyncio.create_task(reconnect_to_server(uri))

# Send an update to other servers about connected clients
async def update_clients_to_servers():
    client_list_message = {
        "type": "client_list_update",
        "server_id": server_id,
        "clients": [{"client-id": client["client-id"], "parent_server": client["parent_server"]} for client in connected_clients]
    }
    await forward_to_servers(client_list_message)

# Handle incoming messages from other servers
async def handle_server_message(message):
    data = json.loads(message)
    
    # Handle public chat message
    if data["type"] == "public_chat":

        chat_message = {
            "type": "public_chat",
            "from": data["from"],
            "message": data["message"],
            "parent_server": server_id
        }
        print(f"Public message from {data['from']} on {server_id}: {data['message']}")

        # Broadcast to local clients
        await broadcast_message_to_clients(chat_message)

        # Forward the message to other servers
        await forward_to_servers(chat_message)

    elif data["type"] == "client_list_update":
        print(f"Received client list update from {data['server_id']}")

# Handle client connection
async def hello_handler(websocket, path):
    try:
        async for message in websocket:
            data = json.loads(message)

            if data["type"] == "hello":
                public_key = data["public-key"]
                client_id = data["fingerprint"]

                if not any(client["client-id"] == client_id for client in connected_clients):
                    connected_clients.append({
                        "client-id": client_id,
                        "public-key": public_key,
                        "websocket": websocket,
                        "parent_server": server_id
                    })
                    print(f"Client added: {client_id} from {server_id}")

                    await update_clients_to_servers()

                response = {"type": "ack", "message": "Hello received, connection established!"}
                await websocket.send(json.dumps(response))

            elif data["type"] == "public_chat":

                chat_message = {
                    "type": "public_chat",
                    "from": data["from"],
                    "message": data["message"],
                    "parent_server": server_id
                }
                await broadcast_message_to_clients(chat_message)
                await forward_to_servers(chat_message)

    except websockets.ConnectionClosed:
        print(f"Client disconnected: {websocket.remote_address}")
        connected_clients[:] = [client for client in connected_clients if client["websocket"] != websocket]
        await update_clients_to_servers()


### MESH SERVER FUNCTIONS ###

# Connect to all servers in the mesh network
async def connect_to_servers():
    for server_uri in server_list:
        if server_uri not in server_connections:
            print(f"Attepmpting to connect to {server_uri}...")
            await connect_to_server(server_uri)

async def connect_to_server(server_uri):
    try:
        websocket = await websockets.connect(server_uri)
        server_connections[server_uri] = websocket
        print(f"Connected to server: {server_uri}")

        # Send initial message to indicate this is a server connection
        initial_message = {"type": "server_hello", "server_id": server_id}
        await websocket.send(json.dumps(initial_message))

        # Start a task to handle incoming messages from this server
        asyncio.create_task(handle_server_connection(websocket, server_uri))

    except Exception as e:
        print(f"Failed to connect to {server_uri}, error: {e}")
        print("Retrying...")
        await reconnect_to_server(server_uri)

# Handle server connections
async def handle_server_connection(websocket, server_uri):
    try:
        async for message in websocket:
            await handle_server_message(message)
    except websockets.ConnectionClosed:
        print(f"Lost connection to server {server_uri}. Attempting to reconnect...")
        await reconnect_to_server(server_uri)

async def reconnect_to_server(server_uri):
    while server_uri not in server_connections:
        print(f"Reconnecting to {server_uri}...")
        try:
            await connect_to_server(server_uri)
        except Exception as e:
            print(f"Failed to reconnect to {server_uri}: {e}")
        await asyncio.sleep(5)

# Start the WebSocket server
async def start_server():
    global server_list
    host_port = input("Server Port: ") #23451
    server_id = input("Server ID: ")
    neighbour_servers = input("Server Connections: ")

    server_list = neighbour_servers.split()
    server_list = ["ws://localhost:" + port for port in server_list]
    print(server_list)

    server = await websockets.serve(hello_handler, "localhost", host_port)
    print(f"WebSocket server started on ws://localhost:{host_port} (Server ID: {server_id})")

    await connect_to_servers()
    await server.wait_closed()

# Run the server
asyncio.get_event_loop().run_until_complete(start_server())
asyncio.get_event_loop().run_forever()
