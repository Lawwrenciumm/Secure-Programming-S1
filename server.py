import json
import asyncio
import websockets
import os

# Global Variables
connected_clients = {}      # Local clients connected to this server
global_clients = {}         # All clients connected across servers
server_connections = {}     # Dictionary of connected servers
server_id = None            # Unique identifier for this server
server_uri = None
UPLOAD_DIR = 'uploads'      # Directory for uploaded files

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Broadcast a message to all connected clients
async def broadcast_to_clients(message):
    if connected_clients:
        await asyncio.gather(
            *[client['websocket'].send(json.dumps(message)) for client in connected_clients.values()],
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
            
            elif data['type'] == 'file_upload':
                await handle_file_upload(websocket, data, client_id)
            elif data['type'] == 'file_download':
                await handle_file_download(websocket, data, client_id)
                
            elif data['type'] == 'private_chat':
                recipient_id = data.get('to')
                if recipient_id in connected_clients:
                    # Recipient is on this server
                    recipient_ws = connected_clients[recipient_id]['websocket']
                    await recipient_ws.send(json.dumps(data))
                elif recipient_id in global_clients:
                    # Recipient is on another server
                    recipient_server_id = global_clients[recipient_id]['server_id']
                    if recipient_server_id in server_connections:
                        server_ws = server_connections[recipient_server_id]['websocket']
                        data['origin_server'] = server_id
                        await server_ws.send(json.dumps(data))
                    else:
                        print(f"Recipient's server {recipient_server_id} is not connected.")
                else:
                    print(f"Recipient {recipient_id} not found.")
            elif data['type'] == 'client_list_request':
                # Prepare the client list
                client_list = [{'id': c['client_id'], 'name': c['name']} for c in global_clients.values()]
                response = {
                    'type': 'client_list',
                    'clients': client_list,
                }
                await websocket.send(json.dumps(response))
            else:
                print(f"Unknown message type from client {client_id}: {data['type']}")
    except websockets.ConnectionClosed:
        print(f"Client {client_id} disconnected.")
        # Remove client from connected_clients and global_clients
        if client_id in connected_clients:
            del connected_clients[client_id]
        if client_id in global_clients:
            del global_clients[client_id]
            # Notify other servers about the client disconnection
            client_disconnect_message = {
                'type': 'client_disconnect',
                'client_id': client_id,
                'server_id': server_id
            }
            await forward_to_servers(client_disconnect_message)

# Handle file upload from a client
async def handle_file_upload(websocket, data, client_id):
    filename = data['filename']
    file_size = data['file_size']

    # Prepare to receive the file
    with open(os.path.join(UPLOAD_DIR, filename), 'wb') as f:
        bytes_received = 0
        while bytes_received < file_size:
            chunk = await websocket.recv()
            f.write(chunk)
            bytes_received += len(chunk)
    
    print(f"File '{filename}' uploaded by {client_id}.")
    # Acknowledge the upload
    await websocket.send(json.dumps({'type': 'file_upload_ack', 'message': 'File uploaded successfully'}))

# Handle file download requests
async def handle_file_download(websocket, data, client_id):
    filename = data['filename']
    file_path = os.path.join(UPLOAD_DIR, filename)

    if os.path.isfile(file_path):
        # Send file size first
        file_size = os.path.getsize(file_path)
        await websocket.send(json.dumps({'type': 'file_download_ack', 'file_size': file_size}))

        # Send the file in chunks
        with open(file_path, 'rb') as f:
            while (chunk := f.read(1024)):  # Read in 1KB chunks
                await websocket.send(chunk)
        
        print(f"File '{filename}' sent to {client_id}.")
    else:
        print(f"File '{filename}' not found for {client_id}.")
        await websocket.send(json.dumps({'type': 'file_download_nack', 'message': 'File not found'}))

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
            elif data['type'] == 'private_chat':
                if data.get('origin_server') == server_id:
                    # Ignore messages originating from this server
                    continue
                recipient_id = data.get('to')
                if recipient_id in connected_clients:
                    # Send directly to the recipient
                    recipient_ws = connected_clients[recipient_id]['websocket']
                    await recipient_ws.send(json.dumps(data))
                elif recipient_id in global_clients:
                    # Forward to the server where the recipient is connected
                    recipient_server_id = global_clients[recipient_id]['server_id']
                    if recipient_server_id != server_id and recipient_server_id != sid:
                        if recipient_server_id in server_connections:
                            server_ws = server_connections[recipient_server_id]['websocket']
                            await server_ws.send(json.dumps(data))
                        else:
                            print(f"Recipient's server {recipient_server_id} is not connected.")
                else:
                    print(f"Recipient {recipient_id} not found.")
            elif data['type'] == 'client_connect':
                client_id = data['client_id']
                client_name = data['name']
                server_of_client = data['server_id']
                global_clients[client_id] = {
                    'client_id': client_id,
                    'name': client_name,
                    'server_id': server_of_client
                }
                print(f"Client {client_name} ({client_id}) connected on server {server_of_client}.")
            elif data['type'] == 'client_disconnect':
                client_id = data['client_id']
                if client_id in global_clients:
                    del global_clients[client_id]
                    print(f"Client {client_id} disconnected from server {data['server_id']}.")
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
        # Remove clients connected to the disconnected server
        clients_to_remove = [cid for cid, info in global_clients.items() if info['server_id'] == sid]
        for cid in clients_to_remove:
            del global_clients[cid]
            print(f"Removed client {cid} from global client list due to server {sid} disconnection.")
        # Attempt to reconnect only if uri is valid
        if uri:
            asyncio.create_task(reconnect_to_server(uri, sid))
        else:
            print(f"No URI available to reconnect to server {sid}.")


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
                # Send local clients to the reconnected server
                for client in connected_clients.values():
                    client_connect_message = {
                        'type': 'client_connect',
                        'client_id': client['client_id'],
                        'name': client['name'],
                        'server_id': server_id
                    }
                    await websocket.send(json.dumps(client_connect_message))
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
            client_name = data.get('name', 'Unknown')
            connected_clients[client_id] = {'client_id': client_id, 'websocket': websocket, 'name': client_name}
            global_clients[client_id] = {'client_id': client_id, 'name': client_name, 'server_id': server_id}
            print(f"Client {client_name} ({client_id}) connected.")
            # Notify other servers about the new client
            client_connect_message = {
                'type': 'client_connect',
                'client_id': client_id,
                'name': client_name,
                'server_id': server_id
            }
            await forward_to_servers(client_connect_message)
            # Send acknowledgment
            await websocket.send(json.dumps({'type': 'ack', 'message': 'Connected to server'}))
            # Start handling client messages
            await handle_client_messages(websocket, client_id)
        elif data['type'] == 'server_hello':
            # Server connection
            sid = data['server_id']
            peer_uri = data.get('uri')
            # Send back our server_hello with our own URI
            await websocket.send(json.dumps({'type': 'server_hello', 'server_id': server_id, 'uri': server_uri}))
            server_connections[sid] = {'websocket': websocket, 'uri': peer_uri}
            print(f"Server {sid} connected.")
            # Send local clients to the connected server
            for client in connected_clients.values():
                client_connect_message = {
                    'type': 'client_connect',
                    'client_id': client['client_id'],
                    'name': client['name'],
                    'server_id': server_id
                }
                await websocket.send(json.dumps(client_connect_message))
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

async def connect_to_server(uri):
    while True:
        try:
            print(f"Connecting to server at {uri}")
            websocket = await websockets.connect(uri)
            # Send server_hello with our own URI
            await websocket.send(json.dumps({'type': 'server_hello', 'server_id': server_id, 'uri': server_uri}))
            # Receive server_hello
            response = await websocket.recv()
            data = json.loads(response)
            if data['type'] == 'server_hello':
                sid = data['server_id']
                peer_uri = data.get('uri')
                server_connections[sid] = {'websocket': websocket, 'uri': peer_uri}
                print(f"Connected to server {sid} at {uri}")
                # Send local clients to the connected server
                for client in connected_clients.values():
                    client_connect_message = {
                        'type': 'client_connect',
                        'client_id': client['client_id'],
                        'name': client['name'],
                        'server_id': server_id
                    }
                    await websocket.send(json.dumps(client_connect_message))
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
    global server_id, server_uri
    # Get server details from the user
    startup = False
    while not startup:
        startup_option = input("Enter Preset Number or manual: ").strip()
        if startup_option == "1":
            host_port = "23451"
            server_id = "1"
            neighbour_servers = "23452"
            startup = True

        elif startup_option == "2":
            host_port = "23452"
            server_id = "2"
            neighbour_servers = "23451"
            startup = True

        elif startup_option.lower() == "manual":
            host_port = input("Server Port: ").strip()
            server_id = input("Server ID: ").strip()
            neighbour_servers = input("Server Connections (space-separated URIs): ").strip()
            startup = True

        else:
            print("Invalid option.")

    server_uri = f"ws://localhost:{host_port}"
    
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
