import json
import asyncio
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import sys
import os
from collections import deque

# Queue to handle specific requests like client list and file operations
request_queue = deque()

# Mapping from names to client IDs (for convenience)
name_to_id_map = {}

# Generate RSA key pair for the client
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize the public key to PEM format
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

# Send the 'hello' message with the client's fingerprint and name
async def send_hello_message(websocket, fingerprint_hex, public_key, from_client):
    hello_message = {
        "type": "hello",
        "fingerprint": fingerprint_hex,
        "public-key": serialize_public_key(public_key),
        "name": from_client
    }
    await websocket.send(json.dumps(hello_message))
    response = await websocket.recv()
    data = json.loads(response)
    if data['message'] == 'Connected to server':
        print("Connection Established")
    else:
        print("Connection Failed")

# Send a public chat message
async def send_public_message(websocket, from_client, message):
    chat_message = {
        "type": "public_chat",
        "from": from_client,
        "message": message,
    }
    await websocket.send(json.dumps(chat_message))

# Send a private chat message
async def send_private_message(websocket, from_client, client_id, recipient_id, message):
    chat_message = {
        "type": "private_chat",
        "from": from_client,
        "from_id": client_id,
        "to": recipient_id,
        "message": message,
    }
    await websocket.send(json.dumps(chat_message))

# Function to upload a file to the server
async def upload_file(websocket, file_path):
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    # Send a file upload message to the server
    upload_message = {
        "type": "file_upload",
        "filename": file_name,
        "file_size": file_size
    }
    await websocket.send(json.dumps(upload_message))

    # Send the file in chunks
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(1024)  # Read in 1KB chunks
            if not chunk:
                break
            await websocket.send(chunk)

    print(f"File '{file_name}' uploaded successfully.")

# Function to download a file from the server
async def download_file(websocket, file_name):
    download_message = {
        "type": "file_download",
        "filename": file_name
    }
    await websocket.send(json.dumps(download_message))

    # Wait for acknowledgment with file size
    response = await websocket.recv()
    data = json.loads(response)

    if data['type'] == 'file_download_ack':
        file_size = data['file_size']
        print(f"Starting download of '{file_name}' ({file_size} bytes)")

        with open(file_name, 'wb') as f:
            bytes_received = 0
            while bytes_received < file_size:
                chunk = await websocket.recv()
                f.write(chunk)
                bytes_received += len(chunk)

        print(f"File '{file_name}' downloaded successfully.")
    else:
        print(f"Error: {data.get('message', 'Failed to download file')}")

# Handle user input from the console
async def handle_user_input(websocket, from_client, client_id):
    loop = asyncio.get_event_loop()
    while True:
        message = await loop.run_in_executor(None, sys.stdin.readline)
        message = message.strip()
        if message.lower() == '/exit':
            print("Exiting chat...")
            await websocket.close()
            sys.exit()
        elif message.lower() == '/clients':
            # Request the list of online clients
            await websocket.send(json.dumps({'type': 'client_list_request'}))
        elif message.startswith('/msg '):
            # Send a private message
            try:
                parts = message.split(' ', 2)
                if len(parts) < 3:
                    print("Usage: /msg recipient_id message")
                    continue
                recipient_id = parts[1]
                private_message = parts[2]
                await send_private_message(websocket, from_client, client_id, recipient_id, private_message)
            except Exception as e:
                print(f"Error sending private message: {e}")
                
        elif message.lower().startswith('/upload'):
            _, file_path = message.split(maxsplit=1)
            request_queue.append(('upload', file_path))  # Add upload request to the queue

        elif message.lower().startswith('/download'):
            _, file_name = message.split(maxsplit=1)
            request_queue.append(('download', file_name))  # Add download request to the queue
        elif message:
            await send_public_message(websocket, from_client, message)

# Handle incoming messages from the server
async def handle_incoming_messages(websocket):
    try:
        async for message in websocket:
            data = json.loads(message)

            # Handle messages based on their type
            if data["type"] == "public_chat":
                sender = data.get("from", "Unknown")
                msg = data.get("message", "")
                print(f"\n[Public] {sender}: {msg}")

            elif data["type"] == "private_chat":
                sender = data.get("from", "Unknown")
                msg = data.get("message", "")
                print(f"\n[Private] {sender}: {msg}")

            elif data["type"] == "ack":
                print(f"Server: {data['message']}")

            elif data["type"] == "client_list":
                clients = data.get("clients", [])
                print("Online clients:")
                for client in clients:
                    print(f"- {client['name']} (ID: {client['id']})")
                    name_to_id_map[client['name']] = client['id']
                    
            elif data["type"] == "file_upload_ack":
                print(f"Server: {data['message']}")

            elif data["type"] == "file_download_nack":
                print(f"Server: {data['message']}")

            else:
                print(f"Received unknown message type: {data}")
             # Handle queued requests for upload/download
            if request_queue:
                operation, file_param = request_queue.popleft()
                if operation == 'upload':
                    await upload_file(websocket, file_param)
                elif operation == 'download':
                    await download_file(websocket, file_param)
                    
    except websockets.ConnectionClosed:
        print("Connection closed by the server.")
        sys.exit()

# Client's main function
async def main():
    startup = False
    while not startup:
        startup_option = input("Enter Preset Number or manual: ").strip()
        if startup_option == "1":
            uri = "ws://localhost:23451"
            startup = True

        elif startup_option == "2":
            uri = "ws://localhost:23452"
            startup = True

        elif startup_option.lower() == "manual":
            uri = input("Enter URI: ").strip()
            startup = True

        else:
            print("Invalid option.")

    # Generate key pair and fingerprint
    private_key, public_key = generate_key_pair()
    fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
    fingerprint.update(serialize_public_key(public_key).encode('utf-8'))
    fingerprint_hex = fingerprint.finalize().hex()
    print(f"Your client ID is: {fingerprint_hex}")

    from_client = input("Enter your name: ").strip()
    if not from_client:
        from_client = "Anonymous"
    
    print("COMMANDS")
    print("/clients                 see all online users")
    print("/msg <id> <message>      private message")
    print("/exit                    exit program")
    print("/upload <file_path>      uploads file")
    print("/download <file_name>    downloads file")
    async with websockets.connect(uri) as websocket:
        await send_hello_message(websocket, fingerprint_hex, public_key, from_client)

        # Start tasks for sending and receiving messages
        send_task = asyncio.create_task(handle_user_input(websocket, from_client, fingerprint_hex))
        receive_task = asyncio.create_task(handle_incoming_messages(websocket))

        # Wait for either task to complete
        done, pending = await asyncio.wait(
            [send_task, receive_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

# Run the client
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient exited manually.")
