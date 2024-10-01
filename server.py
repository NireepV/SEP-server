import websockets
import asyncio
import base64
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.backends import default_backend


PORT = 8080
BUFFER_SIZE = 2048
SERVER_ADDR = "127.0.0.1:8080"


# Setting Up User and Server Lists
class User:
    def __init__(self, ip, port, public_key, websocket):
        self.ip = ip
        self.port = port
        self.public_key = public_key
        self.websocket = websocket

class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


local_user_list = []
server_list = []
num_servers = 2



# Function to generate a public-private key pair for RSA encryption
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key



# Function to Base64 encode
def base64_encode(data):
    return base64.b64encode(data).decode('utf-8')



# Function to Base64 decode
def base64_decode(data):
    return base64.b64decode(data.encode('utf-8'))



# Function to return address in string format
def return_addr(ip, port):
    return f"{ip}:{port}"



# Add users to the local user list
def add_user(public_key, address, port, websocket):
    local_user_list.append(User(address, port, public_key, websocket))
    print(f"User added. Total users: {len(local_user_list)}")



# Add Servers to the Server list
def add_server(address, port):
    server_list.append(Server(address, port))
    print(f"Server added. Total Servers: {len(server_list)}")



# Handle hello messages
async def handle_hello_messages(data, websocket):
    public_key = data["public_key"]
    print(f"Received public key: {public_key}")
    add_user(public_key, "127.0.0.1", PORT, websocket)



# Handle chat messages
async def handle_chat_messages(message, data):
    destination_servers = data["destination_servers"]
    for server_addr in destination_servers:
        if server_addr == SERVER_ADDR:
            print("Message is for the current server. Broadcasting to local clients...")
            for user in local_user_list:
                await user.websocket.send(message)
        else:
            print("Sending to Other Servers")
            server_url = f"ws://{server_addr}"
            async with websockets.connect(server_url) as ws:
                await ws.send(message)
            print(f"Sent to Server {server_addr}")



# Handle public chat messages
async def handle_public_chat_messages(message, websocket):
    for server in server_list: # Using Server List to Send Data to Servers instead of Directly to Clients
        if return_addr(server.ip, server.port) == SERVER_ADDR:
            print("Message is for the current server. Broadcasting to local clients...")
            for user in local_user_list:
                if user.websocket != websocket: 
                    await user.websocket.send(message)
        else:
            server_url = f"ws://{server.ip}:{server.port}"
            async with websockets.connect(server_url) as ws:
                await ws.send(message)
            print(f"Sent to Server {server.ip}:{server.port}")



# Handle public chat messages
async def send_client_update():
    response = {
        "type": "client_update",
        "clients": []
    }

    for user in local_user_list:
        response["clients"].append(user.public_key)
    
    for user in local_user_list:
        await user.websocket.send(json.dumps(response, indent=4))


# Handle client list request
async def handle_client_list_request(websocket):
    response = {
        "type": "client_list",
        "servers": []
    }

    for server in server_list:
        server_info = {
            "address": return_addr(server.ip, server.port),
            "clients": []
        }

        for user in local_user_list:
            if return_addr(user.ip, user.port) == return_addr(server.ip, server.port):  # Check if IPs match
                server_info["clients"].append(user.public_key)

        response["servers"].append(server_info)

    await websocket.send(json.dumps(response, indent=4))



# Function to ping users and remove inactive ones
async def ping_and_remove_inactive_users():
    global local_user_list
    active_users = []

    for user in local_user_list:
        try:
            # Send a ping and wait for a pong response (with a timeout)
            await user.websocket.ping()
            await asyncio.wait_for(user.websocket.pong(), timeout=5)
            active_users.append(user)  # Add user to active users if pong is received
        except asyncio.TimeoutError:
            print(f"User {user.ip}:{user.port} did not respond to ping. Removing...")
        except websockets.exceptions.ConnectionClosed:
            print(f"User {user.ip}:{user.port} disconnected. Removing...")
    
    local_user_list = active_users  # Update local_user_list with only active users
    print(f"Updated user list. Total active users: {len(local_user_list)}")



# Handling incoming messages
async def handle_message(message, websocket):
    data = json.loads(message)

    if data["type"] == "signed_data":
        msg_type = data["data"]["type"]
        if msg_type == "hello":
            await handle_hello_messages(data["data"], websocket)
            await send_client_update()
        elif msg_type == "chat":
            await handle_chat_messages(message, data["data"])
        elif msg_type == "public_chat":
            await handle_public_chat_messages(message, websocket)
    elif data["type"] == "client_list_request":
        await handle_client_list_request(websocket)
    elif data["type"] == "client_update":
        await send_client_update()
    
    
    size = len(local_user_list)
    await ping_and_remove_inactive_users()
    if len(local_user_list) < size :
        print("Sending Client Update after removing user")
        await send_client_update()



# WebSocket server handler
async def websocket_handler(websocket):
    try: 
        async for message in websocket:
            await handle_message(message, websocket)
    except websockets.exceptions.ConnectionClosed:
        await ping_and_remove_inactive_users()
        await send_client_update()



# Starting the server
async def start_server():
    add_server("127.0.0.1", 8080)
    server = await websockets.serve(websocket_handler, "127.0.0.1", PORT)
    print(f"WebSocket server started on port {PORT}")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(start_server())
    asyncio.get_event_loop().run_forever()
