#include "message.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

constexpr auto PORTNOLEN = 10;
constexpr auto ADDRLEN = 80;
int main(int argc, char *argv[]) {
    int opt;

    sa_family_t af = AF_INET;
    bool verbose;
    char addr[ADDRLEN];
    int port;

    union {
        struct sockaddr_in6 saddr6;
        struct sockaddr_in saddr;
    };

    while ((opt = getopt(argc, argv, "a:6vp:")) != -1) {
        switch (opt) {
        case 'a':
            strcpy(addr, optarg);
            break;
        case '6':
            af = AF_INET6;

            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'v':
            verbose = true;
            break;
        default:
            fprintf(stderr, "Usage: %s [-a address] [-p port] [-6] [-v]\n",
                    argv[0]);
            exit(-1);
        }
    }

    if (strlen(addr) == 0) {
        fprintf(stderr, "address option is mandatory\n");
        exit(1);
    }

    int ret;
    if (af == AF_INET6) {
        saddr6.sin6_port = htons(port);
        saddr6.sin6_family = AF_INET6;
        ret = inet_pton(af, addr, &saddr6.sin6_addr);
    } else {
        saddr.sin_port = htons(port);
        saddr.sin_family = AF_INET;
        ret = inet_pton(af, addr, &saddr.sin_addr);
    }

    if (ret <= 0) {
        fprintf(stderr, "inet_pton error for %s (%s)\n", strerror(errno), addr);
        exit(1);
    }

    fprintf(stdout, "Connecting to %s... (port=%d)\n", addr, port);

    int sockfd = socket(af, SOCK_STREAM, 0);

    if (sockfd < 0) {
        fprintf(stderr, "sock_init: %s\n", strerror(errno));
        return -1;
    }

    if (af == AF_INET6) {
        ret = connect(sockfd, (struct sockaddr *)&saddr6,
                      sizeof(struct sockaddr_in6));
    } else {
        ret = connect(sockfd, (struct sockaddr *)&saddr,
                      sizeof(struct sockaddr_in));
    }
    if (ret < 0) {
        fprintf(stderr, "connect() failed: (%d) %s\n", errno, strerror(errno));
        exit(1);
    }

    request r;
    auto name = "qbqqq";
    r.type = request::MessageType::LOGIN;
    r.data = reinterpret_cast<const unsigned char*>(name);
    r.data_length = strlen(name);
    unsigned char buffer[512];
    auto buf = buffer;
    uint32_t length = r.payload_length();
    memcpy(buf, &length, request::length_size);
    buf += request::length_size;
    r.deparse(buf, length);
    if(send(sockfd, buffer, length + request::length_size, 0) < 0){
        fprintf(stderr, "send() failed: (%d) %s\n", errno, strerror(errno));
        exit(1);
    }
    char bbb[21]{};
    recv(sockfd, bbb, 20, 0);
    bbb[20] = 0;
    printf("%s", buf);
}