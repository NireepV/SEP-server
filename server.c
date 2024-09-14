#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 2048
#define PORT_NUM 8080
#define IP_ADDR "127.0.0.1"

int main()
{

    char *ip = IP_ADDR;
    int port = PORT_NUM;

    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size;
    char buffer[BUFFER_SIZE];
    int n;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (server_sock < 0)
    {
        perror("SOCKET ERROR");
        exit(1);
    }
    printf("SOCKET CREATED \n");

    memset(&server_addr, '\0', sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;
    server_addr.sin_addr.s_addr = inet_addr(ip);

    n = bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (n < 0)
    {
        perror("BIND ERROR");
        exit(1);
    }
    printf("BOUND TO PORT %d \n", port);

    listen(server_sock, 5);
    printf("LISTENING....\n");

    while (1)
    {
        addr_size = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr *)&client_sock, &addr_size);
        if (client_sock > -1)
        {
            printf("CLIENT CONNECTED :]\n");
        }

        bzero(buffer, BUFFER_SIZE);
        recv(client_sock, buffer, sizeof(buffer), 0);
        printf("Client: %s\n", buffer);

        bzero(buffer, sizeof(buffer));
        strcpy(buffer, "Server to client, hello :]");
        printf("Server: %s\n", buffer);
        send(client_sock, buffer, strlen(buffer), 0);

        break;
    }

    return 0;
}
