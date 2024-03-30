#ifndef UTILS_HPP
#define UTILS_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <sys/socket.h>

constexpr auto QD = 64;
constexpr auto BUF_SHIFT = 12; /* 4k */
constexpr auto BUFFER_SIZE = 1U << BUF_SHIFT;
constexpr auto CQES = (QD * 16);
constexpr auto BUFFERS = CQES;
constexpr auto BACKLOG = 8;

class TCPSocket {
  private:
    int fd_;
    TCPSocket(int fd) : fd_(fd) {}

  public:
    //! Default: construct an unbound, unconnected TCP socket
    TCPSocket() : fd_(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) {}
};
struct CycleBuffer {
    int end{};
    size_t length{};
    std::unique_ptr<unsigned char[]> data{};

    CycleBuffer() = default;

    CycleBuffer(size_t length_)
        : length(length_), data(std::make_unique<unsigned char[]>(length_)){};

    int consume(const unsigned char * buf, size_t buf_len){
        if(buf_len + size() > length){
            return -1;
        }
        memcpy(data.get() + size(), buf, buf_len);
        return 0;
    }
    size_t size() const {
        return end;
    }
};


#endif // UTILS_HPP