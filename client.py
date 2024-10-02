import asyncio
import json
import websockets
import random
import base64
import hashlib
import sys
from collections import OrderedDict
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

SERVER_ADDR = "127.0.0.1:8080"

public_key = ""
private_key = ""
fingerprint = base64.b64encode(hashlib.sha256(public_key.encode()).digest()).decode()

known_client_list = {}

counter = 0

all_chats = {}

# Function to handle the chat client
async def chat(port):
    global counter, private_key, public_key, known_client_list

    private_key, public_key = load_keys()

    async with websockets.connect(f'ws://localhost:{port}') as websocket:
        
        hello_data = {
            "type": "hello",
            "public_key": public_key
        }

        hello = {
            "type": "signed_data",
            "data": hello_data,
            "counter": counter,
            "signature": generate_message_signature(hello_data)
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
            if message == "": continue
            elif message == "/exit":
                await websocket.close()
                exit(0)
            elif message == "/list":
                count = 0
                for client in known_client_list.keys():
                    print(f"{count}: {client[:50]}")
                    count += 1
            elif message.find("client update:") != -1:
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
                if (message[0].isalpha):
                    selected_recp = int(message[0])
                    formatted_Message, tag = create_chat_message(message[1:], list(known_client_list.keys())[selected_recp])
                    
                    json_data = json.loads(formatted_Message)
                    await websocket.send(json.dumps(json_data)+tag)

            counter += 1

def create_chat_message(message:str, recipient_key:str):
    global counter 
    
    # get destination servers & participant key hashes
    server_dests = [SERVER_ADDR]
    participant_hashes = []
    symm_keys = []

    # AES init vector
    aes_key = get_random_bytes(32)
    nonce = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    # calculate hash for recipient
    pub_key = serialization.load_pem_public_key(str.encode(recipient_key), backend=default_backend)
    enc_aes_key = pub_key.encrypt(
        aes_key,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    b64_enc_aes_key = base64.b64encode(enc_aes_key).decode('ascii')
    symm_keys.append(b64_enc_aes_key)

    # calc sha256 hash for participant key
    hasher = hashlib.sha256()
    hasher.update(recipient_key.encode('ascii'))
    participant_hashes.append(hasher.hexdigest())

    # add sender as first participant
    hasher = hashlib.sha256()
    hasher.update(public_key.encode('ascii'))
    hashed_key = hasher.hexdigest()
    if (hashed_key not in participant_hashes):
        participant_hashes.insert(0, hashed_key)

    msg_chat = {
        "participants": participant_hashes,
        "message":message
    }

    chat_cipher, tag = cipher.encrypt_and_digest(json.dumps(msg_chat).encode('ascii'))
    
    msg_data = {
        "type": "chat",
        "destination_servers": server_dests,
        "iv":base64.b64encode(nonce).decode('ascii'),
        "symm_keys": symm_keys,
        "chat": base64.b64encode(chat_cipher).decode('ascii')
    }

    msg = {
        "type": "signed_data",
        "data": msg_data,
        "counter":counter,
        "signature": generate_message_signature(msg_data)
    }
    
    msg_text = json.dumps(msg)

    return msg_text, base64.b64encode(tag).decode('ascii')

async def receive_messages(websocket):
    global known_client_list, public_key

    while True:
        try:
            response = await websocket.recv()
        except websockets.ConnectionClosedOK:
            break

        if (response[-1] != '}'):
            tag = response[response.rindex('}')+1:len(response)]
            response = response[:response.rindex('}')+1]

        json_msg = json.loads(response)

        # parse message from server
        match json_msg["type"]:
            case "client_list": # server response for client list
                servers = json_msg["servers"]
                for server in servers:
                    address = server["address"]

                    for client_key in server["clients"]:
                        #if (client_key == public_key): continue
                        known_client_list[client_key] = address
            
            case "signed_data": # a message
                messageType = json_msg["data"]["type"]

                match messageType:
                    case "chat":
                        print("recv normal chat")
                        parse_normal_chat(json_msg, tag)
                    case "public_chat":
                        print("recv public chat")

def parse_normal_chat(json_msg, tag):
    global private_key

    decoded_tag = base64.b64decode(tag)
    decoded_nonce = base64.b64decode(json_msg["data"]["iv"])

    can_decrypt = False

    for symm_key in json_msg["data"]["symm_keys"]:
        private = serialization.load_pem_private_key(
            str.encode(private_key),
            password=None,
        )
        
        plain_symm_key = base64.b64decode(symm_key)

        try:
            dec_symm_key = private.decrypt(plain_symm_key, 
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )   
            )

            can_decrypt = True
        except ValueError: # for when it cannot be decoded
            continue
        
    if can_decrypt == False:
        return
    
    decoded_chat = base64.b64decode(json_msg["data"]["chat"])

    decrypt_cipher = AES.new(dec_symm_key, AES.MODE_GCM, nonce=decoded_nonce)
    plain_text = decrypt_cipher.decrypt_and_verify(decoded_chat, decoded_tag)
    print(plain_text)



async def get_user_input():
    global known_client_list

    return await asyncio.get_event_loop().run_in_executor(None, input, "Enter message: ")

def generate_message_signature(data:dict):
    global counter

    data_str = str(data)
    plain_signature = data_str + str(counter)

    sha_hasher = hashlib.sha256()
    sha_hasher.update(plain_signature.encode('ascii'))
    sha256_hash = sha_hasher.digest()

    signature = base64.b64encode(sha256_hash).decode('ascii')

    return signature

def save_file(filename:str, contents, is_bytes=False):
    if (is_bytes):
        file = open(filename, 'wb')
    else:
        file = open(filename, 'w')

    file.write(contents)
    file.close()

## SECTION: Encryption 

def generate_keys(force_regen=False):
    # check if keys exist first
    keys_exist = False

    if (os.path.isfile("private.pem") and os.path.isfile("public.pem")):
        if (open("private.pem", 'r').readline() == '-----BEGIN PRIVATE KEY-----\n'
            and (open("public.pem", 'r').readline() == '-----BEGIN PUBLIC KEY-----\n')):
            keys_exist = True
    else:
        keys_exist = False

    if (keys_exist == False or force_regen == True):
        print("generating keys!")
        private_key = rsa.generate_private_key(  
            public_exponent=65537,  
            key_size=2048,  
            backend=default_backend()  
        )  
        private_pem = private_key.private_bytes(  
            encoding=serialization.Encoding.PEM,  
            format=serialization.PrivateFormat.PKCS8,  
            encryption_algorithm=serialization.NoEncryption()  
        ) 

        save_file("private.pem", private_pem, is_bytes=True)  
        
        # generate public key  
        public_key = private_key.public_key()  
        public_pem = public_key.public_bytes(  
            encoding=serialization.Encoding.PEM,  
            format=serialization.PublicFormat.SubjectPublicKeyInfo  
        ) 

        save_file("public.pem", public_pem, is_bytes=True)  

def load_keys():
    with open("public.pem", "rb") as f:
        public = serialization.load_pem_public_key(
            f.read()
        )

        public_serial = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('ascii')

    with open("private.pem", "rb") as f:
        private = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

        private_serial = private.private_bytes(
            encoding=serialization.Encoding.PEM,  
            format=serialization.PrivateFormat.PKCS8,  
            encryption_algorithm=serialization.NoEncryption() 
        ).decode('ascii')

    return private_serial, public_serial

# Run the client
if __name__ == "__main__":
    generate_keys()

    asyncio.run(chat(8080))
