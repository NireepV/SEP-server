#include <libwebsockets.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <cjson/cJSON.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define PORT 8080
#define BUFFER_SIZE 2048

typedef struct IPAddr{
  char *ip;
  int port;
} addr;

// Setting Up Client List
typedef struct client{
    addr address;
    int public_key;
} User;

User *user_list;
int size = 1;

//Adding Clients into Client List
void add_users(int key, char *address, int port){
    for(int i = 0; i < size; i++){
        if(user_list[i].address.ip == NULL){
            user_list[i].address.ip = address;
            user_list[i].address.port = port;
            user_list[i].public_key = key;
            size++; //increment the size of the list after adding a new client
            
            user_list = realloc(user_list, size * sizeof(User)); //There should always be 1 additional empty user
            break;
        }
    }
}

// WebSocket protocols
void handle_hello_messages(cJSON *data){
    // Get Client's Public Key Like This:    
    cJSON *key = cJSON_GetObjectItemCaseSensitive(data, "public_key");
    printf("THIS IS THE PUBLIC KEY : %d\n", key->valueint);
    
    // Adding Client to the Client List
    add_users(key->valueint, "127.0.0.1", PORT);
}

void handle_chat_messages(cJSON *data){
    // TO DO
}

void handle_public_chat_messages(cJSON *data){
    // Get Client's Public Key Like This:    
    cJSON *sender = cJSON_GetObjectItemCaseSensitive(data, "sender");
    cJSON *message = cJSON_GetObjectItemCaseSensitive(data, "message");
    
    printf("THE SENDERS FINGERPRINT : %d\n", sender->valueint);
    printf("THE SENDERS PUBLIC CHAT MESSAGE : %s\n", message->valuestring);
}

char* handle_client_list_request(cJSON *data) {
    // Create root object
    cJSON *response = cJSON_CreateObject();
    
    // Add type field
    cJSON_AddStringToObject(response, "type", "client_list");
    
    // Create the servers array
    cJSON *servers_array = cJSON_CreateArray();
    
    // Iterate over the user list to create server entries
    for (int i = 0; i < size; i++) {
        // Create a server object
        cJSON *server = cJSON_CreateObject();
        cJSON_AddStringToObject(server, "address", user_list[i].address.ip); // Add the address of the server
        
        // Create clients array for each server
        cJSON *clients_array = cJSON_CreateArray();
        
        // Add the client's public key to the clients array
        cJSON_AddItemToArray(clients_array, cJSON_CreateNumber(user_list[i].public_key));
        
        // Attach clients array to the server object
        cJSON_AddItemToObject(server, "clients", clients_array);
        
        // Add this server object to the servers array
        cJSON_AddItemToArray(servers_array, server);
    }
    
    cJSON_AddItemToObject(response, "servers", servers_array);
    
    char *json_string = cJSON_Print(response);

    cJSON_Delete(response);
    
    return json_string;
}

// WebSocket callback function
static int callback_websocket(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    
    char *buffer;
    char response[BUFFER_SIZE];
    
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:  // When a client connects
            printf("Client connected\n");
            break;

        case LWS_CALLBACK_RECEIVE:  // When a message is received
        buffer = (char *)in;
        
        cJSON *json = cJSON_Parse(buffer);
        if (json == NULL)
        {
            printf("Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        }
        else
        {
            cJSON *jData= cJSON_GetObjectItemCaseSensitive(json, "type"); 
            
            if(strcmp(jData->valuestring,"signed_data") == 0)
            {  // checks to see if it is a standard message or a client list request
                jData = cJSON_GetObjectItemCaseSensitive(json, "data");
                cJSON *jType= cJSON_GetObjectItemCaseSensitive(jData, "type");
                
                if(strcmp(jType->valuestring , "hello") == 0)
                {
                    handle_hello_messages(jData);
                }
                else if(strcmp(jType->valuestring , "chat") == 0)
                {
                    printf("MESSAGE RECIEVED : CHAT\n");
                    
                    // Respond to the Client
                    snprintf(response, sizeof(response), "Server is responding to a Private Message ^_^");
                    lws_write(wsi, (unsigned char *)response, strlen(response), LWS_WRITE_TEXT);
                }
                else if(strcmp(jType->valuestring , "public_chat") == 0)
                {
                    handle_public_chat_messages(jData);
                    
                    // Respond to the Client
                    snprintf(response, sizeof(response), "Server is responding to a Public Message O_O");
                    lws_write(wsi, (unsigned char *)response, strlen(response), LWS_WRITE_TEXT);
                }
            }
            else if(strcmp(jData->valuestring,"client_list_request") == 0)
            {
                // Get Client List from Server Formatted in JSON
                char* json_string = handle_client_list_request(jData);
                
                // Respond to the Client
                snprintf(response, sizeof(response), "%s", json_string);
                lws_write(wsi, (unsigned char *)response, strlen(response), LWS_WRITE_TEXT);
                printf("SENT CLIENT LIST\n");
            }
        }
        
        break;

        case LWS_CALLBACK_CLOSED:  // When a client disconnects
            printf("Client disconnected\n");
            break;

        default:
            break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    {
        "ws-protocol",   // Protocol name (must match in the client-side WebSocket)
        callback_websocket,
        0,
        BUFFER_SIZE,
    },
    { NULL, NULL, 0, 0 }  // Terminator for the protocol list
};

int main() {
    struct lws_context_creation_info context_info;
    struct lws_context *context;

    // Zero out the context info structure
    memset(&context_info, 0, sizeof(context_info));

    context_info.port = PORT;
    context_info.protocols = protocols;
    context_info.gid = -1;
    context_info.uid = -1;

    // Create the WebSocket context
    context = lws_create_context(&context_info);
    if (context == NULL) {
        printf("Failed to create WebSocket context\n");
        return -1;
    }

    printf("WebSocket server started on port %d\n", PORT);
    
    // Allocating Memory for Client List
    user_list = (User *) malloc(size * sizeof(User));

    // Run the WebSocket server loop
    while (1) {
        lws_service(context, 1000);  // Run the event loop for 1 second intervals
    }

    // Clean up the WebSocket context
    lws_context_destroy(context);
    
    free(user_list);

    return 0;
}