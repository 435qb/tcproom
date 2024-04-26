#include "message.hpp"
#include <memory>
#include <sys/socket.h>
#include <sys/uio.h>

template <class T>
static int next(const unsigned char **buf, const unsigned char *end, T *retn) {
    auto length = end - *buf;
    if (sizeof(T) > length) [[unlikely]] {
        return -1;
    }
    *retn = *reinterpret_cast<const T *>(*buf);
    *buf += sizeof(T);
    return 0;
}

int Request::parse() {
    const unsigned char *buf = raw.get();
    const unsigned char *end = buf + raw_length;
    if (next(&buf, end, &type) < 0) [[unlikely]] {
        return -1;
    }
    if (next(&buf, end, &data_length) < 0) [[unlikely]] {
        return -1;
    }
    if (buf + data_length > end) [[unlikely]] {
        return -1;
    }
    if (buf + data_length < end) [[unlikely]] {
        return 1;
    }
    data = buf;
    return 0;
}

void Request::deparse(unsigned char *buf) const {
    memcpy(buf, &type, length_size);
    buf += length_size;

    memcpy(buf, &data_length, length_size);
    buf += length_size;

    memcpy(buf, data, data_length);
}

PayloadParser::Result PayloadParser::parseRequest(Request *request) {
    switch (state) {
    case State::Finished:
        if (buffer.size() < length_size) {
            return Result::NotCompleted;
        }
        buffer.extract_no_check(reinterpret_cast<unsigned char *>(&length),
                                length_size); // strict-alias
        if (length > max_length) {
            return Result::Broken;
        }
        state = State::Length;
        [[fallthrough]];
    case State::Length:
        if (buffer.size() < length) {
            return Result::NotCompleted;
        }
        request->raw = std::make_unique<unsigned char[]>(length);
        buffer.extract_no_check(request->raw.get(), length);
        request->raw_length = length;
        if (request->parse()) {
            return Result::Broken;
        }
        length = 0;
        state = State::Finished;
        break;
    }
    return Result::OK;
}

size_t PayloadParser::consume(const unsigned char *data, size_t length) {
    if (length == 0) {
        return 0;
    }
    return buffer.consume(data, length);
}

int Request::send(int fd) {
    update_len();
    auto *data = const_cast<unsigned char *>(this->data);
    struct iovec iovec[] = {
        {.iov_base = &len, .iov_len = PayloadParser::length_size},
        {.iov_base = &type, .iov_len = PayloadParser::length_size},
        {.iov_base = &data_length, .iov_len = PayloadParser::length_size},
        {.iov_base = data, .iov_len = data_length},
    };

    return writev(fd, iovec, std::extent_v<decltype(iovec)>);
}

struct iovec *Request::gen_iovecs() const{
    update_len();
    auto *len = const_cast<decltype(this->len) *>(&this->len);
    auto *type = const_cast<decltype(this->type) *>(&this->type);
    auto *data_length =
        const_cast<decltype(this->data_length) *>(&this->data_length);
    auto *data = const_cast<unsigned char *>(this->data);

    return new struct iovec[]{
        {len, PayloadParser::length_size},
        {type, PayloadParser::length_size},
        {data_length, PayloadParser::length_size},
        {data, *data_length},
    };
}