#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define PORT 8080
#define BUFFER_SIZE 2048

// WebSocket callback function
static int callback_websocket(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:  // When a client connects
            printf("Client connected\n");
            break;

        case LWS_CALLBACK_RECEIVE:  // When a message is received
            // Print the received message
            printf("Client message: %.*s\n", (int)len, (char *)in);

            // Respond to the client
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response), "Server to client, hello :)");
            lws_write(wsi, (unsigned char *)response, strlen(response), LWS_WRITE_TEXT);
            break;

        case LWS_CALLBACK_CLOSED:  // When a client disconnects
            printf("Client disconnected\n");
            break;

        default:
            break;
    }
    return 0;
}

// WebSocket protocols
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

    // Run the WebSocket server loop
    while (1) {
        lws_service(context, 1000);  // Run the event loop for 1 second intervals
    }

    // Clean up the WebSocket context
    lws_context_destroy(context);

    return 0;
}
