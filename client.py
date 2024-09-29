import json
import asyncio
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import sys
import os
import aiohttp
import subprocess
from collections import deque
import base64

# Queue to handle specific requests like client list and file operations
request_queue = deque()

# Mapping from names to client IDs (for convenience)
name_to_id_map = {}

# At the top of client.py
client_public_keys = {}  # Mapping from client_id to public key

# Generate RSA key pair for the client
def generate_key_pair():
    global private_key, public_key
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

def encrypt_message(message, recipient_public_key_pem):
    # Load the recipient's public key
    recipient_public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    # Encrypt the message
    ciphertext = recipient_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encode the ciphertext in Base64 to send over JSON
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    return ciphertext_b64

def decrypt_message(ciphertext_b64, private_key):
    # Decode the Base64 encoded ciphertext
    ciphertext = base64.b64decode(ciphertext_b64)
    # Decrypt the message
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

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
    # Get the recipient's public key
    recipient_public_key_pem = client_public_keys.get(recipient_id)
    if not recipient_public_key_pem:
        print(f"Public key for recipient {recipient_id} not found.")
        return
    # Encrypt the message
    encrypted_message = encrypt_message(message, recipient_public_key_pem)
    chat_message = {
        "type": "private_chat",
        "from": from_client,
        "from_id": client_id,
        "to": recipient_id,
        "message": encrypted_message,
    }
    await websocket.send(json.dumps(chat_message))

# Function to upload a file via HTTP POST request
async def upload_file_http(url, file_path):
    file_name = os.path.basename(file_path)
    
    async with aiohttp.ClientSession() as session:
        with open(file_path, 'rb') as f:
            files = {'file': (file_name, f)}
            async with session.post(url, data=files) as response:
                if response.status == 200:
                    print(f"File '{file_name}' uploaded successfully via HTTP.")
                else:
                    print(f"Failed to upload file '{file_name}' via HTTP. Status: {response.status}")

# Function to download a file via HTTP GET request
async def download_file_http(url, file_name):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                with open(file_name, 'wb') as f:
                    f.write(await response.read())
                print(f"File '{file_name}' downloaded successfully via HTTP.")
            else:
                print(f"Failed to download file '{file_name}' via HTTP. Status: {response.status}")

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
        elif message.lower() == '/disconnect':
            print("Disconnecting from server...")

            # Send a disconnect message to the server
            disconnect_message = {
                "type": "client_disconnect",
                "client_id": client_id,
                "name": from_client
            }
            await websocket.send(json.dumps(disconnect_message))
            
            await websocket.close()  # Close WebSocket connection
            break  # Stop the input loop and disconnect from server

        elif message.lower() == '/clients':
            # Request the list of online clients
            await websocket.send(json.dumps({'type': 'client_list_request'}))
        elif message.startswith('/msg '):
            parts = message.split(' ', 2)
            if len(parts) < 3:
                print("Usage: /msg <recipient_id> <message>")
                continue
            recipient_id = parts[1]
            private_message = parts[2]
            if recipient_id not in client_public_keys:
                print(f"Public key for recipient {recipient_id} not found. Requesting client list...")
                await websocket.send(json.dumps({'type': 'client_list_request'}))
                # Wait briefly to receive the client list
                await asyncio.sleep(1)
            await send_private_message(websocket, from_client, client_id, recipient_id, private_message)
                
        elif message.lower().startswith('/upload'):
            try:
                _, file_path = message.split(maxsplit=1)

                # Execute the curl command to upload the file
                curl_command = ['curl', '-F', f'file=@{file_path}', 'http://localhost:8080/api/upload']
                result = subprocess.run(curl_command, capture_output=True, text=True)

                # Check if the curl command was successful
                if result.returncode == 0:
                    print(f"File '{file_path}' uploaded successfully.")
                    print(f"Response: {result.stdout}")
                else:
                    print(f"File upload failed with error: {result.stderr}")

            except Exception as e:
                print(f"Error handling upload command: {e}")

        elif message.lower().startswith('/download'):
            try:
                _, file_name = message.split(maxsplit=1)
                
                # Specify the URL for the file download
                download_url = f"http://localhost:8080/api/download/{file_name}"
                
                # Execute the curl command to download the file
                curl_command = ['curl', '-o', file_name, download_url]
                result = subprocess.run(curl_command, capture_output=True, text=True)

                # Check if the curl command was successful
                if result.returncode == 0:
                    print(f"File '{file_name}' downloaded successfully.")
                    print(f"Response: {result.stdout}")
                else:
                    print(f"File download failed with error: {result.stderr}")

            except Exception as e:
                print(f"Error handling download command: {e}")
                
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
                encrypted_msg = data.get("message", "")
                # Decrypt the message
                try:
                    print("Encrypted Message: ", encrypted_msg)
                    decrypted_msg = decrypt_message(encrypted_msg, private_key)
                    print(f"\n[Private] {sender}: {decrypted_msg}")
                except Exception as e:
                    print(f"\n[Private] {sender}: [Unable to decrypt message]")

            elif data["type"] == "ack":
                print(f"Server: {data['message']}")

            elif data["type"] == "client_list":
                clients = data.get("clients", [])
                print("Online clients:")
                for client in clients:
                    print(f"- {client['name']} (ID: {client['id']})")
                    name_to_id_map[client['name']] = client['id']
                    client_public_keys[client['id']] = client['public_key']
                    
            elif data["type"] == "file_upload_url":
                # Server provided an upload URL, initiate HTTP upload
                upload_url = data["url"]
                file_path = data["file_path"]
                await upload_file_http(upload_url, file_path)
            
            elif data["type"] == "file_download_url":
                # Server provided a download URL, initiate HTTP download
                download_url = data["url"]
                file_name = data["filename"]
                await download_file_http(download_url, file_name)

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
                    await websocket.send(json.dumps({"type": "file_upload_request", "file_path": file_param}))
                elif operation == 'download':
                    await websocket.send(json.dumps({"type": "file_download_request", "filename": file_param}))

                    
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
    print("/disconnect              disconnect from server")
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
