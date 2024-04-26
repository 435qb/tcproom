#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include "utils.hpp"
#include <array>
#include <cstdint>
#include <cstring>
enum class MessageType { SYNC };
struct Message {
    using UserIDType = uint64_t;
    UserIDType userID;
};

struct Request {

    enum class MessageType : uint32_t { LOGIN, SEND, LOGOUT } type;
    uint32_t data_length{};
    const unsigned char *data{}; // not owner

    constexpr static auto length_size = sizeof(data_length);

    std::unique_ptr<unsigned char[]> raw{};
    uint32_t raw_length{};

    Request() = default;
    int parse();

    inline uint32_t payload_length() const {
        return length_size + length_size + data_length;
    }

    int send(int fd);

    struct iovec *gen_iovecs() const;

    void update_len() const { len = payload_length(); }

  private:
    void deparse(unsigned char *buf) const;
    mutable uint32_t len;
};

struct PayloadParser {
    using length_type = uint32_t;
    length_type length{};
    constexpr static auto length_size = sizeof(length_type);

    constexpr static auto max_length = BUFFER_SIZE / 2;
    enum class State { Finished, Length } state{State::Finished};
    enum class Result { OK, Broken, NotCompleted };

    CycleBuffer buffer{length_size + max_length};

    Result parseRequest(Request *request);

    size_t consume(const unsigned char *data, size_t length);
};

#endif // MESSAGE_HPP