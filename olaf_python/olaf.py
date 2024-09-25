import websocket as ws
import json
import rel
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

sockets = []
known_servers = []

public_key = ""
private_key = ""

def recv_message(wsapp, message):
    print("Message from server: " + wsapp.url)
    print(message)

def connect_server(address, port, sockets):
    # establish server connection
    socket_app = ws.WebSocketApp(f"ws://{address}:{port}", on_message=recv_message)
    socket_app.run_forever(dispatcher=rel, reconnect=3)

    # save newly connected socket to list
    sockets.append(socket_app)

    # send hello message
    hello = {
        "type": "hello",
        "public_key": public_key
    }

    socket_app.send(json.dumps(hello))
    #print(socket_app.recv())

def request_client_list():
    request = {
        "type": "client_list_request"
    }

    full_response = []

    for socket in sockets:

        socket.send(json.dumps(request))
        response = socket.recv()
        json_response = json.loads(response)

        if json_response["type"] == "client_list":
            servers = json_response["servers"]

            for server in servers:
                full_response.append(server)

    return json.loads(full_response)

def save_file(filename, contents, is_bytes=False):
    if (is_bytes):
        file = open(filename, 'wb')
    else:
        file = open(filename, 'w')

    file.write(contents)
    file.close()

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
    
    rel.signal(2, rel.abort)
    rel.dispatch()

if __name__ == '__main__':
    start()