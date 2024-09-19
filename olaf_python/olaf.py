import websocket as ws
import json

server_socket = None

def connect_server(address, port):
    # establish server connection
    global server_socket
    server_socket = ws.create_connection(f"ws://{address}:{port}")

    # send hello message
    hello = {
        "type": "hello",
        "public_key": "insert_public_key_here"
    }

    server_socket.send(json.dumps(hello))
    print(server_socket.recv())

def request_client_list():
    global server_socket

    request = {
        "type": "client_list_request"
    }

    server_socket.send(json.dumps(request))

    response = server_socket.recv()

    return json.loads(response)

def send_test_message():
    global server_socket
    server_socket.send("test message")
    print(server_socket.recv())