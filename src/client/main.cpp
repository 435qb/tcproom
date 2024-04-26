#include "message.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
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

    PayloadParser parser;

    std::jthread recv_thread([&parser, sockfd]() {
        while (true) {
            Request recv_request;
            auto retn = PayloadParser::Result::OK;
            do {
                unsigned char recv_buf[PayloadParser::max_length];
                int recv_length =
                    recv(sockfd, recv_buf, PayloadParser::max_length, 0);
                if (recv_length < 0) {
                    fprintf(stderr, "recv() failed: (%d) %s\n", errno,
                            strerror(errno));
                    exit(1);
                }
                parser.consume(recv_buf, recv_length);

                retn = parser.parseRequest(&recv_request);
            } while (retn == PayloadParser::Result::NotCompleted);

            if (retn == PayloadParser::Result::Broken) {
                fprintf(stderr, "payload broken\n");
                exit(1);
            }
            switch (recv_request.type) {
            case Request::MessageType::SEND:
                std::cout.write((char *)recv_request.data,
                                recv_request.data_length);
                std::cout << "\n";
                break;
            case Request::MessageType::LOGIN:
            case Request::MessageType::LOGOUT:
            default:
                fprintf(stderr, "request broken\n");
                break;
            }
        }
    });

    std::string name;
    {
        std::cout << "name:";
        std::cin >> name;
        char blank;
        std::cin.get(blank);
        Request r;
        r.type = Request::MessageType::LOGIN;
        r.data = reinterpret_cast<const unsigned char *>(name.data());
        r.data_length = name.size();

        if (r.send(sockfd) < 0) {
            fprintf(stderr, "writev() failed: (%d) %s\n", errno,
                    strerror(errno));
            exit(1);
        }
    }

    std::string curr_text;
    while (std::getline(std::cin, curr_text)) {
        Request r;
        r.type = Request::MessageType::SEND;
        r.data = reinterpret_cast<const unsigned char *>(curr_text.data());
        r.data_length = curr_text.size();

        if (r.send(sockfd) < 0) {
            fprintf(stderr, "writev() failed: (%d) %s\n", errno,
                    strerror(errno));
            exit(1);
        }
    }
}