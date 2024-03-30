#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <cstdint>
#include <cstring>
enum class MessageType{
    SYNC
};
struct Message{
    using UserIDType = uint64_t;
    UserIDType userID;
    

};

struct request {
    enum class MessageType : uint32_t { LOGIN, SEND, LOGOUT } type;
    uint32_t data_length;
    const unsigned char *data; // not owner
    constexpr static auto length_size = sizeof(uint32_t);

    static int parse(const unsigned char *buf, const unsigned char *end,
                     request *request) {
        if (next(&buf, end, &request->type) < 0) {
            return -1;
        }
        if (next(&buf, end, &request->data_length) < 0) {
            return -1;
        }
        if (buf + request->data_length > end) {
            return -1;
        }
        if (buf + request->data_length < end) [[unlikely]] {
            return 1;
        }
        request->data = buf;
        return 0;
    }
    template <class T>
    static int next(const unsigned char **buf, const unsigned char *end,
                    T *retn) {
        auto length = end - *buf;
        if (sizeof(T) > length) {
            return -1;
        }
        *retn = *reinterpret_cast<const T *>(*buf);
        *buf += sizeof(T);
        return 0;
    }

    int deparse(unsigned char *buf, int length){
        if(payload_length() > length){
            return -1;
        }
        memcpy(buf, &type, length_size);
        buf += length_size;

        memcpy(buf, &data_length, length_size);
        buf += length_size;

        memcpy(buf, data, data_length);
        return 0;
    }

    uint32_t payload_length(){
        return length_size + length_size + data_length;
    }
};


struct PayloadParser {
    uint32_t length;
    enum class State{
        Finished, Length, Payload
    } state;

    int parse(){
        switch (state) {
        case State::Finished:

        case State::Length:

        case State::Payload:

            break;
        }
    }

    int parseRequest();
    int parseResponse();
};


#endif // MESSAGE_HPP