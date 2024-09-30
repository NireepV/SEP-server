import websocket as ws
import json
import rel
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hashlib
import tkinter as tk
from threading import Thread

sockets:list[ws.WebSocketApp] = []
known_client_list = {}

public_key = ""
private_key = ""

counter = 0

## SECTION: Websockets & Messages

def recv_message(wsapp, message):
    print("Message received from server: " + wsapp.url)

    json_msg = json.loads(message)

    # parse message from server
    match json_msg["type"]:
        case "client_list": # server response for client list
            servers = json_msg["servers"]
            for server in servers:
                address = server["address"]

                for client_key in server["clients"]:
                    known_client_list[client_key] = address

            send_message('test', [public_key])
        
        case "signed_data": # a message
            messageType = json_msg["data"]["type"]

            match messageType:
                case "chat":
                    print("recv normal chat")
                case "public_chat":
                    print("recv public chat")


def connect_server(address:str, port:str, sockets):
    global counter

    # establish server connection
    socket_app = ws.WebSocketApp(f"ws://{address}:{port}", on_message=recv_message)
    socket_app.run_forever(dispatcher=rel, reconnect=3)

    # save newly connected socket to list
    sockets.append(socket_app)

    data = {
        "type": "hello",
        "public_key": public_key
    }

    # send hello message
    hello = {
        "type": "signed_data",
        "data": data,
        "counter": counter,
        "signature": generate_message_signature(data)
    }

    socket_app.send(json.dumps(hello))

    counter += 1

def request_client_list():
    request = {
        "type": "client_list_request"
    }

    for socket in sockets:
        socket.send(json.dumps(request))

def generate_message_signature(data:dict):
    data_str = str(data)
    plain_signature = data_str + str(counter)

    sha_hasher = hashlib.sha256()
    sha_hasher.update(plain_signature.encode('ascii'))
    sha256_hash = sha_hasher.digest()

    signature = base64.b64encode(sha256_hash).decode('ascii')

    return signature

def send_public_message(message: str):
    global counter, public_key

    hasher = hashlib.sha256()
    hasher.update(public_key.encode('ascii'))
    b64_key = base64.b64encode(hasher.digest()).decode('ascii')

    data = {
        "type": "public_chat",
        "sender": b64_key,
        "message": message
    }

    public_msg = {
        "type": "signed_data",
        "data": data,
        "counter": counter,
        "signature": generate_message_signature(data)
    }

    # send to all servers
    for socket in sockets:
        socket.send(json.dumps(public_msg))

def send_message(message: str, participant_keys:list[str]):
    global counter 
    
    # get destination servers & participant key hashes
    server_dests = []
    participant_hashes = []
    symm_keys = []

    # AES init vector
    aes_key = get_random_bytes(32)
    nonce = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    # calculate hash for all participants
    for key in participant_keys:
        # calc symm key for participant
        pub_key = serialization.load_pem_public_key(str.encode(key), backend=default_backend)
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
        hasher.update(key.encode('ascii'))
        participant_hashes.append(hasher.hexdigest())

        server = known_client_list[key]
        if (server not in server_dests):
            server_dests.append(server)

    # add sender as first participant
    hasher = hashlib.sha256()
    hasher.update(public_key.encode('ascii'))
    participant_hashes.insert(0, hasher.hexdigest())

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
    
    msg_text = json.dumps(msg) + str(tag)

    # send to all destination servers
    for destination in server_dests:
        for socket in sockets:
            if socket.url == "ws://"+destination:
                socket.send(msg_text)

    counter += 1

## SECTION: Misc

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

def start():
    # generate keys!
    generate_keys()

    # load keys!
    global private_key, public_key
    private_key, public_key = load_keys()

    # connect to all known servers
    with open("server_list.json") as fp:
        server_list = json.load(fp)

        for server in server_list["servers"]:
            connect_server(server["address"], server["port"], sockets)
    
    # send request to create known client list from all connected servers
    request_client_list()

    rel.signal(2, rel.abort)
    rel.dispatch()

if __name__ == '__main__':
    start()