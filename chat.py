from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import asyncio
import websockets
import json
import base64
from websockets import WebSocketServerProtocol
from aiohttp import web

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    ).decode('utf-8')

def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data.encode('utf-8'))

def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )
    return signature

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def encrypt_aes_gcm(key, plaintext):
    iv = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def decrypt_aes_gcm(key, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

class Client:
    def __init__(self, server_uri):
        self.server_uri = server_uri
        self.private_key = generate_rsa_key_pair()
        self.public_key_pem = serialize_public_key(self.private_key.public_key())
        self.counter = 0  # Monotonically increasing counter
        self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.public_key_pem.encode('utf-8'))
        return base64.b64encode(digest.finalize()).decode('utf-8')

    async def connect(self):
        self.connection = await websockets.connect(self.server_uri)
        await self.send_hello()
        asyncio.create_task(self.listen())


    async def send_hello(self):
        message = {
            "data": {
                "type": "hello",
                "public_key": self.public_key_pem,
            }
        }
        await self.connection.send(json.dumps(message))

    async def send_chat(self, recipients):
        # Generate AES key
        aes_key = os.urandom(32)
        plaintext_message = "Hello, this is a secure message."
        iv, ciphertext, tag = encrypt_aes_gcm(aes_key, plaintext_message.encode('utf-8'))

        # Encrypt AES key with recipients' public keys (placeholder)
        symm_keys = []
        destination_servers = []
        participants = [self.fingerprint]  # Start with sender's fingerprint

        for recipient in recipients:
            recipient_public_key = load_public_key(recipient['public_key'])
            encrypted_aes_key = recipient_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            symm_keys.append(base64.b64encode(encrypted_aes_key).decode('utf-8'))
            destination_servers.append(recipient['server_address'])
            participants.append(recipient['fingerprint'])

        chat_content = {
            "participants": participants,
            "message": plaintext_message
        }
        chat_json = json.dumps(chat_content)

        # Sign the message
        self.counter += 1
        data_to_sign = chat_json.encode('utf-8') + str(self.counter).encode('utf-8')
        signature = sign_data(self.private_key, data_to_sign)
        recipient_fingerprints = [recipient['fingerprint'] for recipient in recipients]
        signed_data = {
            "type": "signed_data",
            "data": {
                "type": "chat",
                "destination_servers": destination_servers,
                "iv": base64.b64encode(iv).decode('utf-8'),
                "symm_keys": symm_keys,
                "chat": base64.b64encode(ciphertext).decode('utf-8'),
                "recipient_fingerprints": recipient_fingerprints,
                "client-info": {
                    "client-id": self.fingerprint,
                    "server-id": "localhost:12345"
                },
                "time-to-die": "Timestamp"
            },
            "counter": self.counter,
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        await self.connection.send(json.dumps(signed_data))

    async def listen(self):
        try:
            async for message in self.connection:
                await self.handle_message(message)
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed")

    async def handle_message(self, message):
        data = json.loads(message)
        if 'data' in data:
            message_type = data['data'].get('type')
            if message_type == 'chat':
                await self.handle_chat_message(data['data'])
            elif message_type == 'public_chat':
                await self.handle_public_chat_message(data['data'])
            else:
                # Handle other message types
                pass

    async def handle_chat_message(self, data):
        symm_keys_b64 = data.get('symm_keys', [])
        iv_b64 = data.get('iv')
        chat_b64 = data.get('chat')
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(chat_b64)
        tag = None  # Update if tag is used separately
        for symm_key_b64 in symm_keys_b64:
            try:
                symm_key_encrypted = base64.b64decode(symm_key_b64)
                aes_key = self.private_key.decrypt(
                    symm_key_encrypted,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # Decrypt the message
                plaintext = decrypt_aes_gcm(aes_key, iv, ciphertext, tag)
                chat_content = json.loads(plaintext.decode('utf-8'))
                print("Received message:", chat_content['message'])
                break
            except Exception as e:
                continue

    async def handle_public_chat_message(self, data):
        sender_fingerprint = data.get('sender')
        message = data.get('message')
        print(f"Public message from {sender_fingerprint}: {message}")

class Server:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.clients = {}  # Maps client fingerprints to connection and public key
        self.client_counters = {}  # Stores the last counter value for each client
        self.neighbourhood_servers = []  # List of other servers in the neighbourhood
        self.server_id = "YourServerID"  # Unique identifier for this server

    async def handler(self, websocket: websockets.WebSocketServerProtocol, path):
        # Store the websocket connection in a set for cleanup
        try:
            async for message in websocket:
                await self.process_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            await self.client_disconnected(websocket)

    async def process_message(self, websocket, message):
        data = json.loads(message)
        if 'data' in data and data['data']['type'] == 'hello':
            await self.handle_hello(data, websocket)
        elif data.get('type') == 'signed_data':
            await self.handle_signed_data(data, websocket)
        elif data.get('type') == 'client_update':
            await self.handle_client_update(data)
        elif data.get('type') == 'client_update_request':
            await self.send_client_update(websocket)
        else:
            # Unknown message type
            pass

    async def handle_hello(self, data, websocket):
        public_key_pem = data['data']['public_key']
        fingerprint = self.compute_fingerprint(public_key_pem)
        self.clients[fingerprint] = {
            'websocket': websocket,
            'public_key_pem': public_key_pem,
            'counter': 0
        }
        await self.broadcast_client_update()

    def compute_fingerprint(self, public_key_pem):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_key_pem.encode('utf-8'))
        return digest.finalize().hex()

    async def broadcast_client_update(self):
        update_message = {
            "type": "client_update",
            "clients": [client['public_key_pem'] for client in self.clients.values()]
        }
        await self.broadcast_to_neighbours(update_message)

    async def broadcast_to_neighbours(self, message):
        for server_uri in self.neighbourhood_servers:
            try:
                async with websockets.connect(server_uri) as server_ws:
                    await server_ws.send(json.dumps(message))
            except Exception as e:
                print(f"Failed to send message to {server_uri}: {e}")

    async def handle_signed_data(self, data, websocket):
        # Extract the signature, counter, and the actual data
        signature_b64 = data.get('signature')
        counter = data.get('counter')
        signed_data = data.get('data')

        if not signature_b64 or counter is None or not signed_data:
            # Invalid message format
            return

        signature = base64.b64decode(signature_b64)

        # Retrieve the sender's public key using the websocket connection
        sender_fingerprint = None
        for fingerprint, client_info in self.clients.items():
            if client_info['websocket'] == websocket:
                sender_fingerprint = fingerprint
                sender_public_key_pem = client_info['public_key_pem']
                break

        if not sender_fingerprint:
            # Sender not recognized
            return

        # Verify the signature
        sender_public_key = serialization.load_pem_public_key(
            sender_public_key_pem.encode('utf-8')
        )

        # Prepare the data that was signed (data + counter)
        data_to_verify = json.dumps(signed_data).encode('utf-8') + str(counter).encode('utf-8')

        is_valid_signature = verify_signature(sender_public_key, signature, data_to_verify)
        if not is_valid_signature:
            # Invalid signature
            print("Invalid signature from client:", sender_fingerprint)
            return

        # Check the counter to prevent replay attacks
        last_counter = self.clients[sender_fingerprint]['counter']
        if counter <= last_counter:
            # Counter not greater than last received, possible replay attack
            print("Replay attack detected from client:", sender_fingerprint)
            return

        # Update the last counter value
        self.clients[sender_fingerprint]['counter'] = counter

        # Process the message based on its type
        message_type = signed_data.get('type')
        if message_type == 'chat':
            await self.handle_chat_message(signed_data, sender_fingerprint)
        elif message_type == 'public_chat':
            await self.handle_public_chat_message(signed_data, sender_fingerprint)
        else:
            # Unknown signed data type
            pass

    async def handle_chat_message(self, signed_data, sender_fingerprint):
        destination_servers = signed_data.get('destination_servers', [])
        sender_server_id = signed_data.get('client-info', {}).get('server-id')

        for server_address in destination_servers:
            if server_address == self.server_id:
                await self.forward_message_to_clients(signed_data)
            else:
                await self.forward_message_to_server(signed_data, server_address)


    async def handle_public_chat_message(self, signed_data, sender_fingerprint):
        # Broadcast the message to all clients connected to this server
        message = {
            "data": signed_data
        }
        await self.broadcast_to_clients(message)

        # Optionally, forward the message to other servers if required

    async def forward_message_to_clients(self, signed_data):
        recipient_fingerprints = signed_data.get('recipient_fingerprints', [])
        for recipient_fingerprint in recipient_fingerprints:
            client_info = self.clients.get(recipient_fingerprint)
            if client_info and client_info['websocket'] is not None:
                try:
                    await client_info['websocket'].send(json.dumps({"data": signed_data}))
                except Exception as e:
                    print(f"Failed to send message to client {recipient_fingerprint}: {e}")

        # Decrypt the symm_keys to find the intended recipients
        symm_keys_b64 = signed_data.get('symm_keys', [])
        for client_fingerprint, client_info in self.clients.items():
            # Attempt to decrypt each symm_key with the client's public key
            recipient_public_key_pem = client_info['public_key_pem']
            recipient_public_key = serialization.load_pem_public_key(
                recipient_public_key_pem.encode('utf-8')
            )

            # For each symm_key, attempt to decrypt it
            # This is a simplified example; in practice, you would match symm_keys to recipients
            try:
                # Assuming symm_keys are in the same order as participants
                # Here we attempt to decrypt each symm_key; in reality, we need to map them properly
                for symm_key_b64 in symm_keys_b64:
                    symm_key_encrypted = base64.b64decode(symm_key_b64)
                    aes_key = recipient_public_key.decrypt(
                        symm_key_encrypted,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    # If decryption is successful, the message is intended for this client
                    # Forward the message
                    await client_info['websocket'].send(json.dumps({"data": signed_data}))
                    break  # Stop after successfully forwarding to the client
            except Exception:
                # Decryption failed; not intended for this client
                continue

    async def forward_message_to_server(self, signed_data, server_address):
        server_uri = f"ws://{server_address}"
        try:
            async with websockets.connect(server_uri) as server_ws:
                await server_ws.send(json.dumps(signed_data))
        except Exception as e:
            print(f"Failed to forward message to server {server_address}: {e}")

    async def broadcast_to_clients(self, message):
        for client_info in self.clients.values():
            if client_info['websocket'] is not None:
                try:
                    await client_info['websocket'].send(json.dumps(message))
                except Exception as e:
                    print(f"Failed to send message to client: {e}")

    async def handle_client_update(self, data):
        # Update internal client list with clients from other servers
        clients_pem = data.get('clients', [])
        for public_key_pem in clients_pem:
            fingerprint = self.compute_fingerprint(public_key_pem)
            if fingerprint not in self.clients:
                self.clients[fingerprint] = {
                    'websocket': None,  # Not directly connected
                    'public_key_pem': public_key_pem,
                    'counter': 0
                }

    async def send_client_update(self, websocket):
        update_message = {
            "type": "client_update",
            "clients": [client['public_key_pem'] for client in self.clients.values()]
        }
        await websocket.send(json.dumps(update_message))

    async def client_disconnected(self, websocket):
        # Find the client associated with this websocket
        disconnected_fingerprint = None
        for fingerprint, client_info in list(self.clients.items()):
            if client_info['websocket'] == websocket:
                disconnected_fingerprint = fingerprint
                break

        if disconnected_fingerprint:
            # Remove client from the client list
            del self.clients[disconnected_fingerprint]
            print(f"Client {disconnected_fingerprint} disconnected.")
            # Broadcast the client update to other servers
            await self.broadcast_client_update()

    async def start(self):
        self.server = await websockets.serve(self.handler, self.host, self.port)
        print(f"Server started at ws://{self.host}:{self.port}")
        await self.server.wait_closed()


class FileServer:
    def __init__(self):
        self.app = web.Application()
        self.app.add_routes([
            web.post('/api/upload', self.handle_upload),
            web.get('/files/{filename}', self.handle_download)
        ])
        self.files = {}  # In-memory storage for files

    async def handle_upload(self, request):
        reader = await request.multipart()
        field = await reader.next()
        filename = field.filename
        size = 0
        content = bytearray()
        while True:
            chunk = await field.read_chunk()
            if not chunk:
                break
            size += len(chunk)
            content.extend(chunk)
            if size > 10 * 1024 * 1024:  # 10 MB limit
                return web.Response(status=413)

        self.files[filename] = bytes(content)
        file_url = f"/files/{filename}"
        return web.json_response({'file_url': file_url})

    async def handle_download(self, request):
        filename = request.match_info['filename']
        if filename in self.files:
            return web.Response(body=self.files[filename])
        else:
            return web.Response(status=404)

    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', 8080)
        await site.start()
        print("File server started at http://localhost:8080")

async def main():
    server = Server()
    file_server = FileServer()

    server_task = asyncio.create_task(server.start())
    file_server_task = asyncio.create_task(file_server.start())

    # Wait for server to start
    await asyncio.sleep(1)

    # Create multiple clients
    client1 = Client('ws://localhost:12345')
    await client1.connect()

    client2 = Client('ws://localhost:12345')
    await client2.connect()

    # Start listening for messages
    # (Already handled in client.connect())

    # Client1 sends a message to Client2
    recipients = [{
        'public_key': client2.public_key_pem,
        'server_address': server.host + ':' + str(server.port),
        'fingerprint': client2.fingerprint
    }]
    await client1.send_chat(recipients)

    # Keep the main function running
    await asyncio.gather(server_task, file_server_task)


# Run the main function
asyncio.run(main())


server = Server()
file_server = FileServer()
file_server.run()

asyncio.run(main())
asyncio.run(server.start())