import websocket as ws
import json

server_socket = None

def connect_server(address, port):
    global server_socket
    server_socket = ws.create_connection(f"ws://{address}:{port}")

def send_test_message():
    global server_socket
    server_socket.send("test message")
    print(server_socket.recv())