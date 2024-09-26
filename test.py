

# A DUMMY CLIENT, FOR TESTING PURPOSES ONLY 


import asyncio
import json
import websockets
import random


# Function to handle the chat client
async def chat(port):
    counter = 0
    
    async with websockets.connect(f'ws://localhost:{port}') as websocket:
        
        hello = {
            "type": "signed_data",
            "data": {
                    "type": "hello",
                    "public_key": random.randint(323829,993625)
                },
            "counter": counter + random.randint(323829,993625),
            "signature": f"{random.randint(323829,993625)}"
        }
        
        list_clients = {
            "type": "client_list_request",
        }
    
        await websocket.send(json.dumps(hello))
        print(json.dumps(hello))
        print(" ")
        print(" ")
        print("REQUESTING THE CLIENT LIST")
        
        await websocket.send(json.dumps(list_clients))
        
        while True:
            response = await websocket.recv()
            print(f"Received: {response}")
            
            message = input("Enter message: ")
            
            formatted_Message = {
                "type": "signed_data",
                "data": {
                        "type": "public_chat",
                        "sender": random.randint(323829,993625),
                        "message": f"{message}"
                    },
                "counter": counter,
                "signature": "<Base64 signature of data + counter>"
            }
            
            counter = counter + 1
            
            await websocket.send(json.dumps(formatted_Message))

# Run the client
if __name__ == "__main__":
    asyncio.run(chat(8080))
