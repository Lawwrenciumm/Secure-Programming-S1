import json
import asyncio
import websockets
import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from aiohttp import web

# Global Variables
connected_clients = {}      # Local clients connected to this server
global_clients = {}         # All clients connected across servers
server_connections = {}     # Dictionary of connected servers
server_id = None            # Unique identifier for this server
server_uri = None

# Store last counter values to prevent replay attacks
client_counters = {}

# File storage directory
FILE_STORAGE_DIR = 'uploaded_files'

if not os.path.exists(FILE_STORAGE_DIR):
    os.makedirs(FILE_STORAGE_DIR)

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

# Helper function to verify signed data
def verify_signed_data(signed_data, client_public_key_pem, expected_counter, client_id):
    data_json = signed_data['data']
    counter = signed_data['counter']
    signature_b64 = signed_data['signature']
    signature = base64.b64decode(signature_b64)
    data_dict = json.loads(data_json)

    # Check counter for replay attack
    if client_id in client_counters:
        last_counter = client_counters[client_id]
        if counter <= last_counter:
            print(f"Replay attack detected from client {client_id}.")
            return None, None
    else:
        last_counter = -1

    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem.encode('utf-8')
    )

    message_to_verify = data_json + str(counter)
    try:
        client_public_key.verify(
            signature,
            message_to_verify.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        client_counters[client_id] = counter  # Update counter
        return data_dict, counter
    except Exception as e:
        print(f"Signature verification failed for client {client_id}: {e}")
        return None, None

# Handle messages from clients
async def handle_client_messages(websocket, client_id):
    try:
        while True:
            message = await websocket.recv()
            data = json.loads(message)
            if data['type'] != 'signed_data':
                print(f"Invalid message type from client {client_id}")
                continue

            client_info = connected_clients.get(client_id)
            if not client_info:
                print(f"Client {client_id} not found.")
                continue

            client_public_key_pem = client_info['public_key']
            data_dict, counter = verify_signed_data(data, client_public_key_pem, client_info.get('counter', -1), client_id)
            if data_dict is None:
                continue  # Verification failed

            if data_dict['type'] == 'public_chat':
                # Broadcast to local clients
                await broadcast_to_clients(data)
                # Forward to other servers
                await forward_to_servers(data)
            elif data_dict['type'] == 'client_list_request':
                # Send client list
                client_list = [
                    {
                        'id': c['client_id'],
                        'public_key': c['public_key'],
                        'name': c.get('name', c['client_id'][:8])
                    } for c in global_clients.values()
                ]
                response = {
                    'type': 'client_list',
                    'servers': [
                        {
                            'address': server_uri,
                            'clients': client_list
                        }
                    ]
                }
                await websocket.send(json.dumps(response))
            elif data_dict['type'] == 'chat':
                # Forward chat message
                await forward_chat_message(data_dict, data)
            else:
                print(f"Unknown message type from client {client_id}: {data_dict['type']}")

    except websockets.ConnectionClosed:
        print(f"Client {client_id} disconnected.")
    except Exception as e:
        print(f"Exception in handle_client_messages for client {client_id}: {e}")
    finally:
        # Clean up client data
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

async def forward_chat_message(data_dict, original_message):
    # Extract recipients from the unencrypted 'participants' field
    participants = data_dict.get('participants', [])
    for recipient_id in participants:
        if recipient_id in connected_clients:
            # Recipient is on this server
            recipient_ws = connected_clients[recipient_id]['websocket']
            await recipient_ws.send(json.dumps(original_message))
        elif recipient_id in global_clients:
            # Recipient is on another server
            recipient_server_id = global_clients[recipient_id]['server_id']
            if recipient_server_id in server_connections:
                server_ws = server_connections[recipient_server_id]['websocket']
                await server_ws.send(json.dumps(original_message))
            else:
                print(f"Recipient's server {recipient_server_id} is not connected.")
        else:
            print(f"Recipient {recipient_id} not found.")

# Handle messages from servers
async def handle_server_messages(websocket, sid):
    try:
        async for message in websocket:
            data = json.loads(message)
            if data['type'] == 'signed_data':
                # Extract the inner data
                data_json = data['data']
                data_dict = json.loads(data_json)

                if data_dict['type'] == 'public_chat':
                    # Broadcast to local clients
                    await broadcast_to_clients(data)
                    # Forward to other servers excluding the sender
                    await forward_to_servers(data, exclude_server=sid)
                elif data_dict['type'] == 'chat':
                    # Forward chat message to intended recipients
                    await forward_chat_message(data_dict, data)
                else:
                    print(f"Unknown data type in signed_data from server {sid}: {data_dict['type']}")
            elif data['type'] == 'client_connect':
                # Handle client_connect message
                client_id = data['client_id']
                server_of_client = data['server_id']
                client_public_key_pem = data.get('public_key')
                client_name = data.get('name', client_id[:8])
                global_clients[client_id] = {
                    'client_id': client_id,
                    'server_id': server_of_client,
                    'public_key': client_public_key_pem,
                    'name': client_name
                }
                print(f"Client {client_id} connected on server {server_of_client}.")
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
                        'server_id': server_id,
                        'public_key': client['public_key'],
                        'name': client.get('name', client['client_id'][:8])
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

def add_pem_headers(key_pem):
    key_pem = key_pem.strip()
    if not key_pem.startswith('-----BEGIN PUBLIC KEY-----'):
        key_pem = '-----BEGIN PUBLIC KEY-----\n' + key_pem
    if not key_pem.endswith('-----END PUBLIC KEY-----'):
        key_pem = key_pem + '\n-----END PUBLIC KEY-----'
    return key_pem

# Accept incoming connections
async def accept_connection(websocket, path):
    try:
        message = await websocket.recv()
        data = json.loads(message)
        if data['type'] == 'signed_data':
            signed_data = data
            data_json = signed_data['data']
            counter = signed_data['counter']
            signature_b64 = signed_data['signature']
            data_dict = json.loads(data_json)

            if data_dict['type'] == 'hello':
                client_public_key_pem = data_dict['public_key']
                client_name = data_dict.get('name', 'Unknown')
                client_public_key_pem = add_pem_headers(client_public_key_pem)
                client_public_key = serialization.load_pem_public_key(
                    client_public_key_pem.encode('utf-8')
                )

                message_to_verify = data_json + str(counter)
                signature = base64.b64decode(signature_b64)
                try:
                    client_public_key.verify(
                        signature,
                        message_to_verify.encode('utf-8'),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception as e:
                    print(f"Signature verification failed: {e}")
                    await websocket.close()
                    return

                # Generate client_id as fingerprint of public key
                fingerprint = hashes.Hash(hashes.SHA256())
                fingerprint.update(client_public_key_pem.encode('utf-8'))
                client_id = fingerprint.finalize().hex()

                connected_clients[client_id] = {
                    'client_id': client_id,
                    'websocket': websocket,
                    'public_key': client_public_key_pem,
                    'counter': counter,
                    'name': client_name
                }
                global_clients[client_id] = {
                    'client_id': client_id,
                    'server_id': server_id,
                    'public_key': client_public_key_pem,
                    'name': client_name
                }
                print(f"Client {client_name} ({client_id}) connected.")
                # Notify other servers about the new client
                client_connect_message = {
                    'type': 'client_connect',
                    'client_id': client_id,
                    'server_id': server_id,
                    'public_key': client_public_key_pem,
                    'name': client_name
                }
                await forward_to_servers(client_connect_message)
                # Send acknowledgment with client_id
                await websocket.send(json.dumps({'type': 'ack', 'message': 'Connected to server', 'client_id': client_id}))
                # Start handling client messages
                await handle_client_messages(websocket, client_id)
            else:
                print("First message from client is not 'hello'")
                await websocket.close()
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
                    'server_id': server_id,
                    'public_key': client['public_key'],
                    'name': client.get('name', client['client_id'][:8])
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
                        'server_id': server_id,
                        'public_key': client['public_key'],
                        'name': client.get('name', client['client_id'][:8])
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

# Implementing HTTP file upload and download handlers

async def handle_upload(request):
    reader = await request.multipart()
    field = await reader.next()
    if field.name != 'file':
        return web.Response(status=400, text="File not found in request.")

    filename = field.filename
    # Security checks
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit

    if not os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS:
        return web.Response(status=400, text="File type not allowed.")

    size = 0
    with open(os.path.join(FILE_STORAGE_DIR, filename), 'wb') as f:
        while True:
            chunk = await field.read_chunk()
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_SIZE:
                return web.Response(status=400, text="File exceeded size limit of 5MB.")
            f.write(chunk)
    return web.Response(status=200, text=f"File '{filename}' uploaded successfully.")

async def handle_download(request):
    filename = request.match_info.get('filename', None)
    if not filename:
        return web.Response(status=400, text="Filename not provided.")

    file_path = os.path.join(FILE_STORAGE_DIR, filename)
    if not os.path.exists(file_path):
        return web.Response(status=404, text="File not found.")

    return web.FileResponse(path=file_path)

# Function to start the HTTP server
async def start_http_server(host, port):
    app = web.Application()
    app.router.add_post('/api/upload', handle_upload)
    app.router.add_get('/api/download/{filename}', handle_download)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"HTTP Server started at http://{host}:{port}")

# Modify the `start_server` function to start both websocket and HTTP servers

async def start_server():
    global server_id, server_uri
    host_ip = "localhost"
    http_port = 8080  # Default HTTP port

    # Get server details from the user
    startup = False
    while not startup:
        startup_option = input("Enter Preset Number or manual: ").strip()
        if startup_option == "1":
            host_address = "ws://localhost:23451"
            host_port = "23451"
            server_id = "1"
            neighbour_servers = "23452"
            startup = True

        elif startup_option == "2":
            host_address = "ws://localhost:23452"
            host_port = "23452"
            server_id = "2"
            neighbour_servers = "23451"
            startup = True

        elif startup_option == "3":
            host_address = "ws://0.0.0.0:23451"
            host_ip = "0.0.0.0"
            host_port = "23451"
            server_id = "0"
            neighbour_servers = ""
            startup = True

        elif startup_option.lower() == "manual":
            host_ip = input("Server ip: ").strip()
            host_port = input("Server port: ").strip()
            host_address = f"ws://{host_ip}:{host_port}"
            server_id = input("Server ID: ").strip()
            neighbour_servers = input("Server Connections (space-separated ports): ").strip()
            http_port_input = input("HTTP server port (default 8080): ").strip()
            if http_port_input:
                http_port = int(http_port_input)
            startup = True

        else:
            print("Invalid option.")

    server_uri = host_address

    # Parse neighbour server URIs
    server_list = neighbour_servers.strip().split()
    server_list = ["ws://localhost:" + port for port in server_list]

    # Start the websocket server to accept incoming connections
    websocket_server = await websockets.serve(accept_connection, host_ip, int(host_port))
    print(f"WebSocket Server {server_id} started on port {host_port}")

    # Start the HTTP server
    asyncio.create_task(start_http_server(host_ip, http_port))

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
