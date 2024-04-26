#include "utils.hpp"
#include <cassert>

void get_fd_info(int fd, sa_family_t af, const char* &name, int &port){
    sockaddr_in6 addr6;
    sockaddr_in *addr = (sockaddr_in *)&addr6; // type punning

    socklen_t socklength = sizeof(sockaddr_in6);

    if (getpeername(fd, (sockaddr *)(&addr6), &socklength)) {
        fprintf(stderr, "getpeername failed\n");
    }
    char buff[INET6_ADDRSTRLEN + 1];
    void *paddr;

    if (af == AF_INET6)
        paddr = &addr6.sin6_addr;
    else
        paddr = &addr->sin_addr;

    name = inet_ntop(af, paddr, buff, sizeof(buff));
    if (!name)
        name = "<INVALID>";
    port = (int)ntohs(addr->sin_port);
}

void close_connection(int fdidx, sa_family_t af) {
    const char * name;
    int port;
    get_fd_info(fdidx, af, name, port);
    fprintf(stderr, "[%s]:%d disconnected\n\n", name, port);
    close(fdidx);
}
void CycleBuffer::extract_no_check(unsigned char *buf, size_t buf_len) {
    assert(size() >= buf_len);
    auto front = std::min(buf_len, length - start);
    auto back = buf_len - front;
    if (front) {
        memcpy(buf, data.get() + start, front);
    }
    if (back) {
        memcpy(buf + front, data.get(), back);
    }
    start += front + back;
}
size_t CycleBuffer::consume(const unsigned char *buf, size_t buf_len) {
    auto front = std::min(buf_len, length - end);
    auto back = std::min(buf_len - front, start - 0ul);
    if (front) {
        memcpy(data.get() + end, buf, front);
    }
    if (back) {
        memcpy(data.get(), buf + front, back);
    }
    end += front + back;
    return front + back;
}
CycleBuffer::CycleBuffer(size_t length_)
    : length(length_), data(std::make_unique<unsigned char[]>(length_)){};