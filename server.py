import asyncio
import websockets
import json

# Server handler that processes incoming connections
async def hello_handler(websocket, path):
    try:
        # Awaiting a message from the client
        message = await websocket.recv()
        print(f"Received message from client: {message}")
        
        # Parse the received message
        data = json.loads(message)
        
        if data["type"] == "hello":
            # Process the hello message and respond
            response = {"type": "ack", "message": "Hello received, connection established!"}
            await websocket.send(json.dumps(response))
            print(f"Sent response: {response}")
    
    except websockets.ConnectionClosed:
        print("Connection closed")

# Start the WebSocket server
async def start_server():
    server = await websockets.serve(hello_handler, "localhost", 8080)
    print("WebSocket server started on ws://localhost:8080")
    await server.wait_closed()

# Run the server
asyncio.get_event_loop().run_until_complete(start_server())
asyncio.get_event_loop().run_forever()
