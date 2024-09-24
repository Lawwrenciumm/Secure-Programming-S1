import json
import asyncio
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Generating RSA key pair for the client (for testing purposes)
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize the public key to PEM format for sending to the server
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

# Define the 'hello' message that includes the client's fingerprint
async def send_hello_message(server_uri):
    private_key, public_key = generate_key_pair()
    
    # Create the fingerprint (SHA-256 of the public key)
    fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
    fingerprint.update(serialize_public_key(public_key).encode('utf-8'))
    fingerprint_hex = fingerprint.finalize().hex()

    # Create the "hello" message JSON
    hello_message = {
        "type": "hello",
        "fingerprint": fingerprint_hex
    }
    
    # Connect to the server using WebSockets
    async with websockets.connect(server_uri) as websocket:
        # Send the hello message as a JSON object
        await websocket.send(json.dumps(hello_message))
        print(f"Sent hello message: {json.dumps(hello_message)}")
        
        # Wait for the server's response
        response = await websocket.recv()
        print(f"Received response: {response}")

# Define the WebSocket server URI
server_uri = "ws://localhost:8080"  # Server URI where the client connects

# Run the client
asyncio.get_event_loop().run_until_complete(send_hello_message(server_uri))
