import websocket as ws
import json
import rel
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import hashlib

sockets:list[ws.WebSocketApp] = []
known_client_list = {}

public_key = ""
private_key = ""

counter = 0

## SECTION: Websockets & Messages

def recv_message(wsapp, message):
    print("Message received from server: " + wsapp.url)

    # parse message from server
    match message["type"]:
        case "client_list":
            servers = message["servers"]
            for server in servers:
                address = server["address"]

                for client_key in server["clients"]:
                    known_client_list[client_key] = address


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

def send_message(message: str, participant_keys:list[str]):
    # get destination servers & participant key hashes
    server_dests = []
    participant_hashes = []

    for key in participant_keys:
        hasher = hashlib.sha256()
        hasher.update(key.encode('ascii'))
        participant_hashes.append(hasher.digest())

        server = known_client_list[key]
        if (server not in server_dests):
            server_dests.append(server)
    

    msg_data = {
        "type": "chat",
        "destination_servers": server_dests,
        "iv":"",
        "symm_keys": participant_keys,
        "chat": {
            "participants": participant_hashes,
            "message":message
        }
    }

    msg = {
        "type": "signed_data",
        "data": msg_data,
        "counter":counter,
        "signature": generate_message_signature(msg_data)
    }

    for destination in server_dests:
        for socket in sockets:
            if socket.url == destination:
                socket.send(json.dumps(msg))

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
        public = f.read()
    with open("private.pem", "rb") as f:
        private = f.read()

    return private, public

def start():
    # generate keys!
    generate_keys()

    # load keys!
    global private_key, public_key
    b_private_key, b_public_key = load_keys()
    private_key = b_private_key.decode('utf-8')
    public_key = b_public_key.decode('utf-8')

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