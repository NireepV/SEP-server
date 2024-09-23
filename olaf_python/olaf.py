import websocket as ws
import json
import rel

sockets = []
known_servers = []

def recv_message(wsapp, message):
    print("Message from server: " + wsapp.url)
    print(message)

def connect_server(address, port, sockets):
    # establish server connection
    #new_socket = ws.create_connection(f"ws://{address}:{port}")
    socket_app = ws.WebSocketApp(f"ws://{address}:{port}", on_message=recv_message)
    socket_app.run_forever(dispatcher=rel, reconnect=3)

    # save newly connected socket to list
    sockets.append(socket_app)

    # send hello message
    hello = {
        "type": "hello",
        "public_key": "insert_public_key_here"
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

def start():
    # connect to all known servers
    with open("server_list.json") as fp:
        server_list = json.load(fp)

        for server in server_list["servers"]:
            connect_server(server["address"], server["port"], sockets)
    
    rel.signal(2, rel.abort)
    rel.dispatch()

if __name__ == '__main__':
    start()