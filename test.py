import asyncio
import json
import websockets
import random
import base64
import hashlib
import sys

# Generate a random key
key = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=32))

# Calculate the SHA256 fingerprint of the public key
public_key = key  # Using the generated key as the public key
fingerprint = base64.b64encode(hashlib.sha256(public_key.encode()).digest()).decode()


# Function to handle the chat client
async def chat(port):
    counter = 0
    
    async with websockets.connect(f'ws://localhost:{port}') as websocket:
        
        hello = {
            "type": "signed_data",
            "data": {
                    "type": "hello",
                    "public_key": public_key
                },
            "counter": counter + random.randint(323829, 993625),
            "signature": f"{random.randint(323829, 993625)}"
        }
        
        list_clients = {
            "type": "client_list_request",
        }
    
        await websocket.send(json.dumps(hello))
        print("REQUESTING THE CLIENT LIST")
        
        await websocket.send(json.dumps(list_clients))
        
        # Create a task to receive messages
        asyncio.create_task(receive_messages(websocket))

        while True:
            message = await get_user_input()
            
            formatted_Message = {
                "type": "signed_data",
                "data": {
                        "type": "public_chat",
                        "sender": fingerprint,
                        "message": message
                    },
                "counter": counter,
                "signature": "<Base64 signature of data + counter>"
            }
            
            counter += 1
            
            await websocket.send(json.dumps(formatted_Message))


async def receive_messages(websocket):
    while True:
        response = await websocket.recv()
        # Clear the current line and print the incoming message
        sys.stdout.write("\r" + " " * 50 + "\r")  # Clear the line
        print(f"Received: {response}")
        sys.stdout.write("Enter message: ")
        sys.stdout.flush()


async def get_user_input():
    return await asyncio.get_event_loop().run_in_executor(None, input, "Enter message: ")


# Run the client
if __name__ == "__main__":
    asyncio.run(chat(8080))
