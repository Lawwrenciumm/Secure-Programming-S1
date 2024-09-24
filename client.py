import json
import asyncio
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import sys
from collections import deque

# Queue to handle specific requests like client list
request_queue = deque()

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
        "fingerprint": fingerprint_hex,
        "public-key": serialize_public_key(public_key)
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

    # Add request type to the queue so handle_incoming_messages knows what to expect
    request_queue.append("client_list")

# Function to send a public chat message
async def send_public_message(websocket, from_client, message):
    chat_message = {
        "type": "public_chat",
        "from": from_client,
        "message": message
    }
    await websocket.send(json.dumps(chat_message))

# Coroutine to handle user input
async def handle_user_input(websocket, from_client):
    loop = asyncio.get_event_loop()
    while True:
        # Read user input asynchronously
        message = await loop.run_in_executor(None, sys.stdin.readline)
        message = message.strip()
        if message.lower() == '/exit':
            print("Exiting chat...")
            await websocket.close()
            sys.exit()
        elif message.lower() == '/clients':
            await request_client_list(websocket)
        elif message:
            await send_public_message(websocket, from_client, message)

# Coroutine to handle incoming messages
async def handle_incoming_messages(websocket):
    try:
        async for message in websocket:
            data = json.loads(message)

            # Handle messages based on their type
            if data["type"] == "public_chat":
                sender = data.get("from", "Unknown")
                msg = data.get("message", "")
                print(f"\n{sender}: {msg}")

            elif data["type"] == "ack":
                print(f"Server: {data['message']}")

            elif data["type"] == "client_list" and request_queue and request_queue[0] == "client_list":
                request_queue.popleft()  # Remove the request type from the queue
                print("Online Clients:")
                for server in data.get("servers", []):
                    print(f"Server ID: {server.get('server-id')}, Address: {server.get('address')}")
                    for client in server.get("clients", []):
                        print(f" - Client ID: {client.get('client-id')}")

            else:
                print(f"Received unknown message type: {data}")

    except websockets.ConnectionClosed:
        print("Connection closed by the server.")
        sys.exit()

# Client's main function
async def main():
    uri = "ws://203.7.78.43:23451"
    
    from_client = input("Enter your name: ").strip()
    if not from_client:
        from_client = "Anonymous"

    async with websockets.connect(uri) as websocket:
        await send_hello_message(websocket)

        # Start tasks for sending and receiving messages
        send_task = asyncio.create_task(handle_user_input(websocket, from_client))
        receive_task = asyncio.create_task(handle_incoming_messages(websocket))

        # Wait for either task to complete (which shouldn't happen under normal operation)
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
