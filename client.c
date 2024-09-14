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

    int sock;
    struct sockaddr_in addr;
    socklen_t addr_size;
    char buffer[BUFFER_SIZE];
    int n;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0)
    {
        perror("SOCKET ERROR");
        exit(1);
    }
    printf("SOCKET CREATED \n");

    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = port;
    addr.sin_addr.s_addr = inet_addr(ip);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    printf("CONNECTED TO SERVER :] \n");

    bzero(buffer, sizeof(buffer));
    strcpy(buffer, "HEELLEW");
    printf("Client: %s\n", buffer);
    send(sock, buffer, strlen(buffer), 0);

    bzero(buffer, BUFFER_SIZE);
    recv(sock, buffer, sizeof(buffer), 0);
    printf("Server: %s\n", buffer);

    return 0;
}