import asyncio
import websockets
import json
import base64
import rsa
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

# Encryption constants
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32
AES_IV_SIZE = 16

# RSA key pair generation (public/private)
(private_key, public_key) = rsa.newkeys(RSA_KEY_SIZE)

# Create a message signature
def sign_message(message, counter, private_key):
    data = json.dumps(message).encode() + str(counter).encode()
    signature = rsa.sign(data, private_key, 'SHA-256')
    return base64.b64encode(signature).decode()

# Verify the message signature
def verify_message_signature(message, signature, counter, public_key):
    data = json.dumps(message).encode() + str(counter).encode()
    signature = base64.b64decode(signature)
    try:
        rsa.verify(data, signature, public_key)
        return True
    except rsa.VerificationError:
        return False

# AES encryption
def encrypt_aes(plaintext, key):
    iv = os.urandom(AES_IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

# AES decryption
def decrypt_aes(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv, ciphertext = ciphertext[:AES_IV_SIZE], ciphertext[AES_IV_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Send a message over WebSocket
async def send_message(ws, message_type, data, counter, private_key):
    message = {
        "type": "signed_data",
        "data": data,
        "counter": counter,
        "signature": sign_message(data, counter, private_key)
    }
    await ws.send(json.dumps(message))

# Handle incoming messages
async def handle_message(message, public_key):
    try:
        msg = json.loads(message)
        if not verify_message_signature(msg["data"], msg["signature"], msg["counter"], public_key):
            print("Invalid signature. Possible attack.")
            return
        print("Message received:", msg["data"])
    except Exception as e:
        print(f"Failed to handle message: {e}")

# WebSocket client implementation
async def chat_client(uri):
    counter = 0
    async with websockets.connect(uri) as ws:
        # Send hello message with public key
        await send_message(ws, "hello", {"type": "hello", "public_key": public_key.save_pkcs1().decode()}, counter, private_key)
        counter += 1
        
        while True:
            try:
                incoming_message = await ws.recv()
                await handle_message(incoming_message, public_key)
            except websockets.ConnectionClosed:
                print("Connection closed")
                break

# WebSocket server implementation
async def chat_server(websocket, path):
    async for message in websocket:
        await handle_message(message, public_key)

# Start WebSocket server
async def start_server():
    server = await websockets.serve(chat_server, "localhost", 12345)
    print("Server started on ws://localhost:12345")
    await server.wait_closed()

# Main function to start server or client
if __name__ == "__main__":
    mode = input("Do you want to run the server or client? (server/client): ").strip()

    if mode == "server":
        asyncio.get_event_loop().run_until_complete(start_server())
    else:
        uri = "ws://localhost:12345"
        asyncio.get_event_loop().run_until_complete(chat_client(uri))
