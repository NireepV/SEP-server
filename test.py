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
        print(key)
        print("REQUESTING THE CLIENT LIST")
        
        await websocket.send(json.dumps(list_clients))
        
        # Create a task to receive messages
        asyncio.create_task(receive_messages(websocket))

        while True:
            message = await get_user_input()
            if message.find("client update:") != -1:
                formatted_Message = {
                    "type": "client_update",
                }
                
                await websocket.send(json.dumps(formatted_Message))
                
            elif message.find("public:") != -1 :
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
                
                await websocket.send(json.dumps(formatted_Message))
                
            else:
                formatted_Message = {
                    "type": "signed_data",
                    "data": {
                        "type": "chat",
                        "destination_servers": [
                            "127.0.0.1:8080"
                        ],
                        "iv": "<Base64 encoded (AES initialisation vector)>",
                        "symm_keys": [
                            "<Base64 encoded (AES key encrypted with recipient's public RSA key)>",
                        ],
                        "chat": {
                                "participants": [
                                    "<Fingerprint of sender comes first>",
                                    "<Fingerprints of recipients>",
                                ],
                                "message": message
                            }
                    },
                    "counter": counter,
                    "signature": "<Base64 signature of data + counter>"
                }
                
                await websocket.send(json.dumps(formatted_Message))

            counter += 1


async def receive_messages(websocket):
    while True:
        response = await websocket.recv()
        sys.stdout.write("\r" + " " * 50 + "\r")  # Clear the line
        print(f"Received: {response}")
        sys.stdout.write("Enter message: ")
        sys.stdout.flush()


async def get_user_input():
    return await asyncio.get_event_loop().run_in_executor(None, input, "Enter message: ")


# Run the client
if __name__ == "__main__":
    asyncio.run(chat(8080))
