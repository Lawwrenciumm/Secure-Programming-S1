import json
import asyncio
import websockets
import aiohttp
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import sys
import os
import base64
import time
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

request_queue = asyncio.Queue()
name_to_id_map = {}
client_public_keys = {}
trusted_clients = {}
id_to_name_map = {}  # Mapping from client IDs to usernames
short_id_to_full_id = {}  # Mapping of short IDs to full IDs
last_message_time = 0
MAX_MESSAGE_LENGTH = 250
counter = 0  # Message counter for replay attack prevention
client_id = None  # Initialize client_id as None

# To store unique filenames received from the server
uploaded_files = {}

def load_or_generate_keypair():
    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        with open(private_key_file, 'rb') as f:
            password = getpass("Enter passphrase for your private key: ").encode()
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=default_backend()
            )
        with open(public_key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        print("Loaded existing keypair from files.")
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        password = getpass("Set a passphrase for your private key: ").encode()
        with open(private_key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            ))
        with open(public_key_file, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Generated new keypair and saved to files.")
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def create_signed_message(data, private_key, counter):
    data_json = json.dumps(data, separators=(',', ':'))
    message_to_sign = data_json + str(counter)
    signature = private_key.sign(
        message_to_sign.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    signed_message = {
        'type': 'signed_data',
        'data': data_json,
        'counter': counter,
        'signature': signature_b64
    }
    return signed_message

def normalize_pem(pem_str):
    pem_str = pem_str.strip()
    if not pem_str.startswith('-----BEGIN PUBLIC KEY-----'):
        pem_str = '-----BEGIN PUBLIC KEY-----\n' + pem_str
    if not pem_str.endswith('-----END PUBLIC KEY-----'):
        pem_str = pem_str + '\n-----END PUBLIC KEY-----'
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
    trusted_clients = {}
    if not os.path.exists(filename):
        return trusted_clients

    with open(filename, 'r') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == '-----BEGIN TRUSTED CLIENT-----':
            i += 1
            username = lines[i].strip()
            i += 1
            # Read the public key
            public_key_lines = []
            while i < len(lines):
                line = lines[i].strip()
                if line == '-----END TRUSTED CLIENT-----':
                    break
                public_key_lines.append(lines[i])
                i += 1
            public_key_pem = '\n'.join(public_key_lines).strip()
            public_key_pem = normalize_pem(public_key_pem)
            trusted_clients[username] = public_key_pem
        i += 1
    return trusted_clients

def add_trusted_client(username, public_key_pem):
    with open('trusted_clients.txt', 'a') as f:
        f.write('-----BEGIN TRUSTED CLIENT-----\n')
        f.write(f'{username}\n')
        f.write(f'{public_key_pem}\n')
        f.write('-----END TRUSTED CLIENT-----\n')
    # Reload the trusted clients
    global trusted_clients
    trusted_clients = load_trusted_clients()
    print(f"Added '{username}' to trusted clients.")

async def send_hello_message(websocket, public_key, from_client):
    global counter, client_id  # Add client_id as global
    data = {
        "type": "hello",
        "public_key": serialize_public_key(public_key),
        "name": from_client
    }
    signed_message = create_signed_message(data, private_key, counter)
    await websocket.send(json.dumps(signed_message))
    counter += 1
    response = await websocket.recv()
    data = json.loads(response)
    if data.get('message') == 'Connected to server':
        client_id = data.get('client_id')  # Capture client_id
        print("Connection Established")
    else:
        print("Connection Failed")

async def send_public_message(websocket, from_client, message):
    global counter
    data = {
        "type": "public_chat",
        "sender": from_client,
        "message": message
    }
    signed_message = create_signed_message(data, private_key, counter)
    await websocket.send(json.dumps(signed_message))
    counter += 1

async def send_private_message(websocket, from_client, recipient_id, message):
    global counter
    if not client_id:
        print("Client ID not set.")
        return
    recipient_public_key_pem = client_public_keys.get(recipient_id)
    if not recipient_public_key_pem:
        print(f"Public key for recipient {recipient_id} not found.")
        return

    recipient_name = id_to_name_map.get(recipient_id, recipient_id[:8])

    # Check if recipient is trusted
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

    # Generate AES key and IV
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV

    # Encrypt the chat object
    chat_object = {
        "chat": {
            "participants": [
                client_id,
                recipient_id
            ],
            "message": message
        }
    }
    chat_json = json.dumps(chat_object, separators=(',', ':'))

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(chat_json.encode('utf-8')) + encryptor.finalize()
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

    # Encrypt the AES key with recipient's public key
    recipient_public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')

    data = {
        "type": "chat",
        "participants": [recipient_id],  # Include recipients here
        "destination_servers": [],
        "iv": iv_b64,
        "symm_keys": [
            encrypted_aes_key_b64
        ],
        "chat": ciphertext_b64
    }
    signed_message = create_signed_message(data, private_key, counter)
    await websocket.send(json.dumps(signed_message))
    counter += 1

async def handle_user_input(websocket, from_client):
    global last_message_time, counter
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
            await websocket.close()
            sys.exit()

        elif message.lower() == '/clients':
            data = {
                "type": "client_list_request"
            }
            signed_message = create_signed_message(data, private_key, counter)
            await websocket.send(json.dumps(signed_message))
            counter += 1

        elif message.startswith('/msg '):
            parts = message.split(' ', 2)
            if len(parts) < 3:
                print("Usage: /msg <recipient_id_or_name> <message>")
                continue
            recipient_input = parts[1]
            private_message = parts[2]

            # Try to resolve recipient as username
            recipient_id = name_to_id_map.get(recipient_input)
            if not recipient_id:
                # Try to resolve recipient as short ID
                recipient_id = short_id_to_full_id.get(recipient_input)
            if not recipient_id:
                print(f"Recipient {recipient_input} not found.")
                continue
            await send_private_message(websocket, from_client, recipient_id, private_message)

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

        elif message.lower().startswith('/upload '):
            try:
                _, file_path = message.split(maxsplit=1)
                upload_url = 'http://localhost:8080/api/upload'  # Replace with your server's upload endpoint
                unique_filename = await upload_file_http(upload_url, file_path)
                if unique_filename:
                    uploaded_files[file_path] = unique_filename  # Store mapping
            except Exception as e:
                print(f"Error handling upload command: {e}")

        elif message.lower().startswith('/download '):
            try:
                _, unique_filename = message.split(maxsplit=1)
                download_url = f'http://localhost:8080/api/download/{unique_filename}'  # Use unique filename
                await download_file_http(download_url, unique_filename)
            except Exception as e:
                print(f"Error handling download command: {e}")

        elif message:
            await send_public_message(websocket, from_client, message)

        last_message_time = time.time()

async def handle_incoming_messages(websocket):
    try:
        async for message in websocket:
            data = json.loads(message)

            if data["type"] == "client_list":
                servers = data.get("servers", [])
                print("Online clients:")
                for server in servers:
                    clients = server.get("clients", [])
                    for client in clients:
                        client_id_server = client['id']
                        short_id = client_id_server[:8]
                        short_id_to_full_id[short_id] = client_id_server  # Map short ID to full ID
                        client_public_key_pem = client['public_key']
                        client_public_key_pem = normalize_pem(client_public_key_pem)
                        client_public_keys[client_id_server] = client_public_key_pem
                        username = client.get('name', short_id)
                        name_to_id_map[username] = client_id_server
                        id_to_name_map[client_id_server] = username  # Add this line
                        print(f"- {username} (ID: {short_id})")

            elif data["type"] == "signed_data":
                data_json = data['data']
                data_dict = json.loads(data_json)
                if data_dict["type"] == "public_chat":
                    sender_name = data_dict.get("sender", "Unknown")
                    message_text = data_dict.get("message", "")
                    print(f"\n[Public] {sender_name}: {message_text}")
                elif data_dict["type"] == "chat":
                    iv_b64 = data_dict["iv"]
                    symm_keys = data_dict["symm_keys"]
                    ciphertext_b64 = data_dict["chat"]

                    # Decrypt AES key
                    encrypted_aes_key_b64 = symm_keys[0]  # Assuming single recipient
                    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
                    aes_key = private_key.decrypt(
                        encrypted_aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    # Decrypt message
                    iv = base64.b64decode(iv_b64)
                    ciphertext = base64.b64decode(ciphertext_b64)
                    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    chat_data = json.loads(plaintext.decode('utf-8'))
                    participants = chat_data["chat"]["participants"]
                    message_text = chat_data["chat"]["message"]
                    sender_id = participants[0]
                    sender_name = id_to_name_map.get(sender_id, sender_id[:8])

                    # Check if sender is trusted
                    sender_public_key_pem = client_public_keys.get(sender_id)
                    trusted_public_key_pem = trusted_clients.get(sender_name)
                    if trusted_public_key_pem:
                        if not are_keys_equal(trusted_public_key_pem, sender_public_key_pem):
                            print(f"\n[WARNING] Sender '{sender_name}' public key does not match the trusted key.")
                    else:
                        print(f"\n[WARNING] The sender '{sender_name}' is not in your trusted clients.")

                    print(f"\n[Private] {sender_name}: {message_text}")
                else:
                    print(f"Received unknown message type: {data}")
    except websockets.ConnectionClosed:
        print("Connection closed by the server.")
        sys.exit()

async def upload_file_http(url, file_path):
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        raise ValueError("File exceeded size limit of 5MB")

    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif'}

    original_file_name = os.path.basename(file_path)
    if not os.path.splitext(original_file_name)[1].lower() in ALLOWED_EXTENSIONS:
        raise ValueError("File type not allowed")

    async with aiohttp.ClientSession() as session:
        with open(file_path, 'rb') as f:
            data = aiohttp.FormData()
            data.add_field('file', f, filename=original_file_name)
            async with session.post(url, data=data) as response:
                if response.status == 200:
                    unique_filename = await response.text()
                    print(f"File '{original_file_name}' uploaded successfully via HTTP.")
                    print(f"Unique filename: {unique_filename}")
                    return unique_filename  # Return the unique filename
                else:
                    print(f"Failed to upload file '{original_file_name}' via HTTP. Status: {response.status}")
                    return None

async def download_file_http(url, save_as_filename):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                with open(save_as_filename, 'wb') as f:
                    f.write(await response.read())
                print(f"File '{save_as_filename}' downloaded successfully via HTTP.")
            else:
                print(f"Failed to download file '{save_as_filename}' via HTTP. Status: {response.status}")

async def main():
    global private_key, public_key, private_key_file, public_key_file, trusted_clients
    global counter
    global client_id  # Add this line
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

    # Generate key pair
    private_key, public_key = load_or_generate_keypair()
    trusted_clients = load_trusted_clients()

    from_client = input("Enter your name: ").strip()
    if not from_client:
        from_client = "Anonymous"

    print("COMMANDS")
    print("/clients                         see all online users")
    print("/msg <id_or_name> <message>      private message")
    print("/disconnect                      disconnect from server")
    print("/trust <username>                add a user to your trusted clients")
    print("/upload <file_path>              upload a file")
    print("/download <filename>             download a file using unique filename")

    async with websockets.connect(uri) as websocket:
        await send_hello_message(websocket, public_key, from_client)

        # Request client list after connecting
        data = {
            "type": "client_list_request"
        }
        signed_message = create_signed_message(data, private_key, counter)
        await websocket.send(json.dumps(signed_message))
        counter += 1

        # Start tasks for sending and receiving messages
        send_task = asyncio.create_task(handle_user_input(websocket, from_client))
        receive_task = asyncio.create_task(handle_incoming_messages(websocket))

        # Wait for either task to complete
        done, pending = await asyncio.wait(
            [send_task, receive_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient exited manually.")
