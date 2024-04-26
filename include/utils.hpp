#ifndef UTILS_HPP
#define UTILS_HPP

#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>

constexpr auto QD = 64;
constexpr auto BUF_SHIFT = 12; /* 4k */
constexpr auto BUFFER_SIZE = 1U << BUF_SHIFT;
constexpr auto CQES = (QD * 16);
constexpr auto BUFFERS = CQES;
constexpr auto BACKLOG = 8;



void get_fd_info(int fd, sa_family_t af, const char* &name, int &port);

void close_connection(int fdidx, sa_family_t af);

struct CycleBuffer {
    int start{};
    int end{};
    size_t length{};
    std::unique_ptr<unsigned char[]> data{};

    CycleBuffer() = default;

    CycleBuffer(size_t length_);

    size_t consume(const unsigned char *buf, size_t buf_len);
    inline size_t size() const {
        return (end + length - start) % length;
    }

    void extract_no_check(unsigned char *buf, size_t buf_len);
};


#endif // UTILS_HPP