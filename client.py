import json
import asyncio
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Generate RSA key pair for the client (for testing purposes)
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
async def send_hello_message(websocket):
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
    
    # Send the hello message as a JSON object
    await websocket.send(json.dumps(hello_message))
    print(f"Sent hello message: {json.dumps(hello_message)}")
        
    # Wait for the server's acknowledgment response
    response = await websocket.recv()
    print(f"Received response: {response}")

# Function to request and display the list of online clients
async def request_client_list(websocket):
    # Send a client_list_request message to the server
    client_list_request = {"type": "client_list_request"}
    await websocket.send(json.dumps(client_list_request))
    print("Requested client list.")
    
    # Receive and display the client list response from the server
    client_list_response = await websocket.recv()
    response_data = json.loads(client_list_response)
    
    print("Client list response received:")
    for server in response_data.get("servers", []):
        print(f"Server ID: {server['server-id']}, Address: {server['address']}")
        for client in server["clients"]:
            print(f" - Client ID: {client['client-id']}, Public Key: {client['public-key']}")

# Main function to handle client interaction
async def client_interaction(server_uri):
    async with websockets.connect(server_uri) as websocket:
        # Send the initial hello message to the server
        await send_hello_message(websocket)

        # Interactive loop to keep the client running
        while True:
            user_input = input("Enter 'list' to request the client list, or 'exit' to disconnect: ").strip().lower()

            if user_input == 'list':
                # Request the list of online clients
                await request_client_list(websocket)
            elif user_input == 'exit':
                print("Disconnecting...")
                break
            else:
                print("Invalid input. Please enter 'list' or 'exit'.")

# Define the WebSocket server URI
server_uri = "ws://localhost:8080"  # Server URI where the client connects

# Run the client
asyncio.get_event_loop().run_until_complete(client_interaction(server_uri))
