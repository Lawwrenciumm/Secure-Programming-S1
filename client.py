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
import time

request_queue = deque()
name_to_id_map = {}
client_public_keys = {}
trusted_clients = {}
last_message_time = 0
MAX_MESSAGE_LENGTH = 250

def load_or_generate_keypair():
    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        # Load the private key
        with open(private_key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,  # Use a password if you encrypt the private key
                backend=default_backend()
            )
        # Load the public key
        with open(public_key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        print("Loaded existing keypair from files.")
    else:
        # Generate a new keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        # Save the keys to files
        with open(private_key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()  # Use encryption if desired
            ))
        with open(public_key_file, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Generated new keypair and saved to files.")
    return private_key, public_key

# Serialize the public key to PEM format
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def normalize_pem(pem_str):
    # Remove leading and trailing whitespace
    pem_str = pem_str.strip()
    # Ensure headers and footers are present
    if not pem_str.startswith('-----BEGIN PUBLIC KEY-----'):
        pem_str = '-----BEGIN PUBLIC KEY-----\n' + pem_str
    if not pem_str.endswith('-----END PUBLIC KEY-----'):
        pem_str = pem_str + '\n-----END PUBLIC KEY-----'
    # Remove any extra blank lines
    lines = pem_str.splitlines()
    lines = [line.strip() for line in lines if line.strip()]
    return '\n'.join(lines) + '\n'

def are_keys_equal(key_pem1, key_pem2):
    try:
        key_pem1 = normalize_pem(key_pem1)
        key_pem2 = normalize_pem(key_pem2)

        key1 = serialization.load_pem_public_key(
            key_pem1.encode('utf-8'),
            backend=default_backend()
        )
        key2 = serialization.load_pem_public_key(
            key_pem2.encode('utf-8'),
            backend=default_backend()
        )
        return key1.public_numbers() == key2.public_numbers()
    except Exception as e:
        print(f"Error comparing keys: {e}")
        return False

def load_trusted_clients(filename='trusted_clients.txt'):
    if not os.path.exists(filename):
        print(f"Trusted clients file '{filename}' not found.")
        return trusted_clients

    with open(filename, 'r') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == '-----BEGIN TRUSTED CLIENT-----':
            i += 1
            # Read the username
            username = lines[i].strip()
            i += 1
            # Read the public key
            public_key_lines = []
            while i < len(lines) and lines[i].strip() != '-----END TRUSTED CLIENT-----':
                public_key_lines.append(lines[i])
                i += 1
            public_key_pem = '\n'.join(public_key_lines).strip()
            # Remove extra blank lines
            public_key_pem = '\n'.join([line.strip() for line in public_key_pem.splitlines() if line.strip() != ''])
            # Store the public key against the username
            trusted_clients[username] = public_key_pem
        i += 1
    return trusted_clients

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

async def send_private_message(websocket, from_client, client_id, recipient_id, message):
    # Get the recipient's public key
    recipient_public_key_pem = client_public_keys.get(recipient_id)
    if not recipient_public_key_pem:
        print(f"Public key for recipient {recipient_id} not found.")
        return

    # Get the recipient's name from the id
    recipient_name = None
    for name, cid in name_to_id_map.items():
        if cid == recipient_id:
            recipient_name = name
            break

    # Verify the recipient's public key against trusted clients
    trusted_public_key_pem = trusted_clients.get(recipient_name)
    if trusted_public_key_pem:
        if not are_keys_equal(trusted_public_key_pem, recipient_public_key_pem):
            print(f"WARNING: Recipient '{recipient_name}' public key does not match the trusted key.")
            proceed = input("Do you still want to send the message? (yes/no): ").strip().lower()
            if proceed != 'yes':
                print("Message not sent.")
                return
        else:
            print("[Public key verified, message sent.]")
    else:
        print(f"WARNING: Recipient '{recipient_name}' is not in your trusted clients.")
        proceed = input("Do you still want to send the message? (yes/no): ").strip().lower()
        if proceed != 'yes':
            print("Message not sent.")
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

def add_trusted_client(username, public_key_pem):
    with open('trusted_clients.txt', 'a') as f:
        f.write('\n-----BEGIN TRUSTED CLIENT-----\n')
        f.write(f'{username}\n')
        f.write(f'{public_key_pem}\n')
        f.write('-----END TRUSTED CLIENT-----\n')
    # Reload the trusted clients
    global trusted_clients
    trusted_clients = load_trusted_clients()
    print(f"Added '{username}' to trusted clients.")

# Function to upload a file via HTTP POST request
async def upload_file_http(url, file_path):
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        raise ValueError("File exceeded size limit of 5MB")
    
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif'}
    
    file_name = os.path.basename(file_path)
    if not os.path.splitext(file_name)[1].lower() in ALLOWED_EXTENSIONS:
        raise ValueError("File type not allowed")
    
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
    global last_message_time
    loop = asyncio.get_event_loop()
    while True:
        message = await loop.run_in_executor(None, sys.stdin.readline)
        message = message.strip()

        current_time = time.time()
        time_since_last_message = current_time - last_message_time
        
        
        if len(message) > MAX_MESSAGE_LENGTH:
                print(f"Message too long. Please limit your message to {MAX_MESSAGE_LENGTH} characters.")
                continue
        if time_since_last_message < 1:
            print(f"Please wait {1 - time_since_last_message:.2f} seconds before sending another message.")
            continue
        
        if message.lower() == '/disconnect':
            print("Disconnecting from server...")

            # Send a disconnect message to the server
            disconnect_message = {
                "type": "client_disconnect",
                "client_id": client_id,
                "name": from_client
            }
            await websocket.send(json.dumps(disconnect_message))
            
            await websocket.close()  # Close WebSocket connection
            sys.exit() 

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

        elif message.lower().startswith('/trust '):
            try:
                _, username = message.split(maxsplit=1)
                recipient_id = name_to_id_map.get(username)
                if not recipient_id:
                    print(f"User '{username}' not found.")
                    continue
                recipient_public_key_pem = client_public_keys.get(recipient_id)
                if not recipient_public_key_pem:
                    print(f"Public key for '{username}' not found.")
                    continue
                add_trusted_client(username, recipient_public_key_pem)
            except Exception as e:
                print(f"Error adding trusted client: {e}")
                
        elif message:
            await send_public_message(websocket, from_client, message)
            
        last_message_time = time.time()

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
                    client_id = client['id']
                    client_name = client['name']
                    client_public_key_pem = client['public_key']
                    client_public_key_pem = normalize_pem(client_public_key_pem)
                    client_public_keys[client_id] = client_public_key_pem
                    name_to_id_map[client_name] = client_id

                    # Verify the client against trusted clients
                    trusted_public_key_pem = trusted_clients.get(client_name)
                    if trusted_public_key_pem:
                        if are_keys_equal(trusted_public_key_pem, client_public_key_pem):
                            print(f"- {client_name} (ID: {client_id}) [Trusted]")
                        else:
                            print(f"- {client_name} (ID: {client_id}) [WARNING: Public key does not match trusted key]")
                    else:
                        print(f"- {client_name} (ID: {client_id}) [Untrusted]")

                    
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

def load_trusted_clients(filename='trusted_clients.txt'):
    trusted_clients = {}
    if not os.path.exists(filename):
        print(f"Trusted clients file '{filename}' not found.")
        return trusted_clients

    with open(filename, 'r') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == '-----BEGIN TRUSTED CLIENT-----':
            i += 1
            # Read the username
            username = lines[i].strip()
            i += 1
            # Read the public key
            public_key_lines = []
            while i < len(lines) and lines[i].strip() != '-----END TRUSTED CLIENT-----':
                public_key_lines.append(lines[i])
                i += 1
            public_key_pem = '\n'.join(public_key_lines).strip()
            # Store the public key against the username
            trusted_clients[username] = public_key_pem
        i += 1
    return trusted_clients

# Client's main function
async def main():
    global file_server, private_key, public_key, private_key_file, public_key_file, trusted_clients
    startup = False
    while not startup:
        startup_option = input("Enter Preset Number or manual: ").strip()
        if startup_option == "1":
            uri = "ws://localhost:23451"
            startup = True
            private_key_file = 'private_key.pem'
            public_key_file = 'public_key.pem'

        elif startup_option == "2":
            uri = "ws://localhost:23452"
            startup = True
            private_key_file = 'private_key_1.pem'
            public_key_file = 'public_key_1.pem'

        elif startup_option.lower() == "manual":
            file_server = input("Enter <ip-address>:<port>: ")
            uri = f"ws://{file_server}"
            startup = True

        else:
            print("Invalid option.")

    # Generate key pair and fingerprint
    private_key, public_key = load_or_generate_keypair()
    trusted_clients = load_trusted_clients()
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
    print("/upload <file_path>      uploads file")
    print("/download <file_name>    downloads file")
    print("/trust <username>        add a user to your trusted clients")

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
