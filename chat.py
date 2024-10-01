import websocket as ws
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hashlib
import tkinter as tk
import threading
import queue

class Chat(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Tkinter App")
        self.geometry("500x700")

        self.message_entry = tk.Entry(self)
        self.message_entry.pack()
        self.send_button = tk.Button(self, text="Send", command=self.send_public_message)
        self.send_button.pack()

        self.sockets:list[ws.WebSocketApp] = []
        self.known_client_list = {}
        self.websocket_queue = queue.Queue()

        self.public_key = ""
        self.private_key = ""

        self.counter = 0

        self.generate_keys()

        # load keys!
        self.private_key, self.public_key = self.load_keys()

        # setup sockets
        with open("server_list.json") as fp:
            server_list = json.load(fp)
            for server in server_list["servers"]:
                address = server["address"]
                port = server["port"]
                self.websocket_queue.put(f"ws://{address}:{port}")
            
        self.start_websockets()

    def start_websockets(self):
        thread = threading.Thread(target=self.websocket_worker)
        thread.start()

    def websocket_worker(self):
        while True:
            websocket_url = self.websocket_queue.get()
            socket = ws.WebSocketApp(websocket_url, on_open=self.connection_made, on_message=self.recv_message)
            self.sockets.append(socket)
            socket.run_forever()
            self.websocket_queue.task_done()
    
    def send_public_message(self, message: str = "hello!"):
        print("send")
        hasher = hashlib.sha256()
        hasher.update(self.public_key.encode('ascii'))
        b64_key = base64.b64encode(hasher.digest()).decode('ascii')

        data = {
            "type": "public_chat",
            "sender": b64_key,
            "message": message
        }

        public_msg = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": self.generate_message_signature(data)
        }
        
        for socket in self.sockets:
            socket.send(json.dumps(public_msg))

    def send_message(self, message: str, participant_keys:list[str]):
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

            server = self.known_client_list[key]
            if (server not in server_dests):
                server_dests.append(server)

        # add sender as first participant
        hasher = hashlib.sha256()
        hasher.update(self.public_key.encode('ascii'))
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
            "counter": self.counter,
            "signature": self.generate_message_signature(msg_data)
        }
        
        msg_text = json.dumps(msg) + str(tag)

        # send to all destination servers
        for destination in server_dests:
            for socket in self.sockets:
                if socket.url == "ws://"+destination:
                    socket.send(msg_text)

        self.counter += 1
    
    def connection_made(self, wsapp):
        data = {
            "type": "hello",
            "public_key": self.public_key
        }

        # send hello message
        hello = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": self.generate_message_signature(data)
        }

        wsapp.send(json.dumps(hello))

        self.counter += 1

    def recv_message(self, wsapp, message):
        print("Message received from server: " + wsapp.url)

        json_msg = json.loads(message)

        # parse message from server
        match json_msg["type"]:
            case "client_list": # server response for client list
                servers = json_msg["servers"]
                for server in servers:
                    address = server["address"]

                    for client_key in server["clients"]:
                        self.known_client_list[client_key] = address
            
            case "signed_data": # a message
                messageType = json_msg["data"]["type"]

                match messageType:
                    case "chat":
                        print("recv normal chat")
                    case "public_chat":
                        print("recv public chat")

    def generate_message_signature(self, data:dict):
        data_str = str(data)
        plain_signature = data_str + str(self.counter)

        sha_hasher = hashlib.sha256()
        sha_hasher.update(plain_signature.encode('ascii'))
        sha256_hash = sha_hasher.digest()

        signature = base64.b64encode(sha256_hash).decode('ascii')

        return signature

    ## SECTION: Misc

    def save_file(filename:str, contents, is_bytes=False):
        if (is_bytes):
            file = open(filename, 'wb')
        else:
            file = open(filename, 'w')

        file.write(contents)
        file.close()

    ## SECTION: Encryption 

    def generate_keys(self, force_regen=False):
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

            self.save_file("private.pem", private_pem, is_bytes=True)  
            
            # generate public key  
            public_key = private_key.public_key()  
            public_pem = public_key.public_bytes(  
                encoding=serialization.Encoding.PEM,  
                format=serialization.PublicFormat.SubjectPublicKeyInfo  
            ) 

            self.save_file("public.pem", public_pem, is_bytes=True)  

    def load_keys(self):
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

if __name__ == "__main__":
    app = Chat()
    app.mainloop()