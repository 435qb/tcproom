#include <arpa/inet.h>
#include <cstdint>
#include <errno.h>
#include <memory>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>

#include "liburing.h"
#include "utils.hpp"
#include "message.hpp"


struct user_data {
    int index;
    int fd;
};

struct client_ctx {
    std::unique_ptr<unsigned char[]> buf;
    int curr_idx;
    int length; // <0 means length is not completed like 123 | 4
    std::string name;

    // clear except name
    void clear_state() {
        buf = nullptr;
        curr_idx = 0;
        length = 0;
    }
};

struct ctx {
    struct io_uring ring{};
    struct io_uring_buf_ring *buf_ring{};
    unsigned char *buffer_base{};
    // struct msghdr msg;
    sa_family_t af{AF_INET};
    bool verbose{false};
    // struct sendmsg_ctx send[BUFFERS];
    std::unordered_map<int, client_ctx> links{BACKLOG};
    size_t buf_ring_size{};
};

static unsigned char *get_buffer(struct ctx *ctx, int idx) {
    return ctx->buffer_base + (idx << BUF_SHIFT);
}

static int setup_buffer_pool(struct ctx *ctx) {
    int ret, i;
    void *mapped;
    struct io_uring_buf_reg reg = {
        .ring_addr = 0, .ring_entries = BUFFERS, .bgid = 0};

    ctx->buf_ring_size = (sizeof(struct io_uring_buf) + BUFFER_SIZE) * BUFFERS;
    mapped = mmap(NULL, ctx->buf_ring_size, PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mapped == MAP_FAILED) {
        fprintf(stderr, "buf_ring mmap: %s\n", strerror(errno));
        return -1;
    }
    ctx->buf_ring = (struct io_uring_buf_ring *)mapped;

    io_uring_buf_ring_init(ctx->buf_ring);

    reg = (struct io_uring_buf_reg){.ring_addr = (unsigned long)ctx->buf_ring,
                                    .ring_entries = BUFFERS,
                                    .bgid = 0};
    ctx->buffer_base =
        (unsigned char *)ctx->buf_ring + sizeof(struct io_uring_buf) * BUFFERS;

    ret = io_uring_register_buf_ring(&ctx->ring, &reg, 0);
    if (ret) {
        fprintf(stderr,
                "buf_ring init failed: %s\n"
                "NB This requires a kernel version >= 6.0\n",
                strerror(-ret));
        return ret;
    }

    for (i = 0; i < BUFFERS; i++) {
        io_uring_buf_ring_add(ctx->buf_ring, get_buffer(ctx, i), BUFFER_SIZE, i,
                              io_uring_buf_ring_mask(BUFFERS), i);
    }
    io_uring_buf_ring_advance(ctx->buf_ring, BUFFERS);

    return 0;
}

static int setup_context(struct ctx *ctx) {
    struct io_uring_params params;
    int ret;

    memset(&params, 0, sizeof(params));
    params.cq_entries = QD * 8;
    params.flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN |
                   IORING_SETUP_CQSIZE;

    ret = io_uring_queue_init_params(QD, &ctx->ring, &params);
    if (ret < 0) {
        fprintf(stderr,
                "queue_init failed: %s\n"
                "NB: This requires a kernel version >= 6.0\n",
                strerror(-ret));
        return ret;
    }

    ret = setup_buffer_pool(ctx);
    if (ret)
        io_uring_queue_exit(&ctx->ring);

    // memset(&ctx->msg, 0, sizeof(ctx->msg));
    // ctx->msg.msg_namelen = sizeof(struct sockaddr_storage);
    // ctx->msg.msg_controllen = CONTROLLEN;
    return ret;
}

static int setup_sock(sa_family_t af, int port) {
    int ret;
    int fd;
    uint16_t nport = port <= 0 ? 0 : htons(port);

    fd = socket(af, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "sock_init: %s\n", strerror(errno));
        return -1;
    }

    if (af == AF_INET6) {
        struct sockaddr_in6 addr6 = {.sin6_family = af,
                                     .sin6_port = nport,
                                     .sin6_addr = IN6ADDR_ANY_INIT};

        ret = bind(fd, (struct sockaddr *)&addr6, sizeof(addr6));
    } else {
        struct sockaddr_in addr = {
            .sin_family = af, .sin_port = nport, .sin_addr = {INADDR_ANY}};

        ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    }

    if (ret) {
        fprintf(stderr, "sock_bind: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    if (port <= 0) {
        int port;
        struct sockaddr_storage s;
        socklen_t sz = sizeof(s);

        if (getsockname(fd, (struct sockaddr *)&s, &sz)) {
            fprintf(stderr, "getsockname failed\n");
            close(fd);
            return -1;
        }

        port = ntohs(((struct sockaddr_in *)&s)->sin_port);
        fprintf(stderr, "port bound to %d\n", port);
    }
    if (listen(fd, BACKLOG) < 0) {
        fprintf(stderr, "listen: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static void cleanup_context(struct ctx *ctx) {
    munmap(ctx->buf_ring, ctx->buf_ring_size);
    io_uring_queue_exit(&ctx->ring);
}

static bool get_sqe(struct ctx *ctx, struct io_uring_sqe **sqe) {
    *sqe = io_uring_get_sqe(&ctx->ring);

    if (!*sqe) {
        io_uring_submit(&ctx->ring);
        *sqe = io_uring_get_sqe(&ctx->ring);
    }
    if (!*sqe) {
        fprintf(stderr, "cannot get sqe\n");
        return true;
    }
    return false;
}

static int add_recv(struct ctx *ctx, int idx) {
    struct io_uring_sqe *sqe;

    if (get_sqe(ctx, &sqe))
        return -1;

    io_uring_prep_recv_multishot(sqe, idx, nullptr, 0, 0);
    // sqe->flags |= IOSQE_FIXED_FILE;

    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = 0;
    user_data ud{BUFFERS + 1, idx};
    io_uring_sqe_set_data64(sqe, *(uint64_t *)&ud);
    return 0;
}

int add_accept(ctx *ctx, int fdidx) {
    struct io_uring_sqe *sqe;

    if (get_sqe(ctx, &sqe))
        return -1;

    io_uring_prep_multishot_accept(sqe, fdidx, NULL, NULL, 0);
    sqe->flags |= IOSQE_FIXED_FILE;

    user_data ud{BUFFERS + 2};
    io_uring_sqe_set_data64(sqe, *(uint64_t *)&ud);
    return 0;
}

static void recycle_buffer(struct ctx *ctx, int idx) {
    io_uring_buf_ring_add(ctx->buf_ring, get_buffer(ctx, idx), BUFFER_SIZE, idx,
                          io_uring_buf_ring_mask(BUFFERS), 0);
    io_uring_buf_ring_advance(ctx->buf_ring, 1);
}

int handle_request(struct ctx *ctx, request *r, int idx, int fdidx) {
    struct io_uring_sqe *sqe;
    if (get_sqe(ctx, &sqe))
        return -1;

    switch (r->type) {

    case request::MessageType::LOGIN:

    case request::MessageType::SEND:
        break;
    case request::MessageType::LOGOUT:

        break;
    }
    char buffer[512] = "sad";
    io_uring_prep_send(sqe, fdidx, buffer, 20, 0);
    user_data ud{idx, fdidx};
    io_uring_sqe_set_data64(sqe, *(uint64_t *)&ud);

    return 0;
}
static int process_cqe_send(struct ctx *ctx, struct io_uring_cqe *cqe) {
    auto *ud = (user_data *)&cqe->user_data;
    auto idx = ud->index;
    if (cqe->res < 0)
        fprintf(stderr, "bad send %s\n", strerror(-cqe->res));
    recycle_buffer(ctx, idx);
    return 0;
}

static int process_cqe_recv(struct ctx *ctx, struct io_uring_cqe *cqe) {
    int ret, idx;
    struct io_uring_recvmsg_out *o;
    auto *ud = (user_data *)&cqe->user_data;
    auto fdidx = ud->fd;
    idx = cqe->flags >> 16;

    if(cqe->res == 0){
        ctx->links.erase(fdidx);
        recycle_buffer(ctx, idx);
        if (ctx->verbose) {
            sockaddr_in6 addr6;
            socklen_t socklength;
            sockaddr_in *addr = (sockaddr_in *)&addr6;
            
            if (getpeername(fdidx, (sockaddr *)(&addr6), &socklength)) {
                fprintf(stderr, "getpeername failed\n");
            }
            char buff[INET6_ADDRSTRLEN + 1];
            const char *name;
            void *paddr;

            if (ctx->af == AF_INET6)
                paddr = &addr6.sin6_addr;
            else
                paddr = &addr->sin_addr;

            name = inet_ntop(ctx->af, paddr, buff, sizeof(buff));
            if (!name)
                name = "<INVALID>";
            fprintf(stderr, "[%s]:%d disconnected\n\n", name,
                    (int)ntohs(addr->sin_port));
        }
        close(fdidx);
        return 0;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        ret = add_recv(ctx, fdidx);
        if (ret)
            return ret;
    }

    if (cqe->res == -ENOBUFS)
        return 0;

    if (!(cqe->flags & IORING_CQE_F_BUFFER) || cqe->res < 0) {
        fprintf(stderr, "recv cqe bad res %d\n", cqe->res);
        if (cqe->res == -EFAULT || cqe->res == -EINVAL)
            fprintf(stderr, "NB: This requires a kernel version >= 6.0\n");
        return -1;
    }
    // parse payload

    ssize_t length = cqe->res;
    auto buf = get_buffer(ctx, idx);
    auto &client_ctx = ctx->links[fdidx];

    if (ctx->verbose) {
        sockaddr_in6 addr6;
        socklen_t socklength = sizeof(sockaddr_in6);
        sockaddr_in *addr = (sockaddr_in *)&addr6;
        if (getpeername(fdidx, (sockaddr *)(&addr6), &socklength)) {
            fprintf(stderr, "getpeername failed\n");
        }
        char buff[INET6_ADDRSTRLEN + 1];
        const char *name;
        void *paddr;

        if (ctx->af == AF_INET6)
            paddr = &addr6.sin6_addr;
        else
            paddr = &addr->sin_addr;

        name = inet_ntop(ctx->af, paddr, buff, sizeof(buff));
        if (!name)
            name = "<INVALID>";
        fprintf(stderr, "received %ld bytes from [%s]:%d\n\n", length, name,
                (int)ntohs(addr->sin_port));
    }

    if (client_ctx.buf) {
        auto *const curr = client_ctx.buf.get();
        if (client_ctx.length < 0) {
            auto count = request::length_size - client_ctx.curr_idx;
            memcpy(curr + client_ctx.curr_idx, buf, count);
            buf += count;
            length -= count;
            client_ctx.length = *reinterpret_cast<uint32_t *>(curr);
            client_ctx.curr_idx = request::length_size;
        }
        auto count = client_ctx.length - client_ctx.curr_idx;
        memcpy(curr + client_ctx.curr_idx, buf, count);
        buf += count;
        length -= count;

        if (client_ctx.length > BUFFER_SIZE) { // invalid
            fprintf(stderr, "maxium data length\n");
            recycle_buffer(ctx, idx);
            client_ctx.clear_state();
            return 0;
        }

        request r;
        if (request::parse(curr + request::length_size, curr + length, &r) <
            0) {
            fprintf(stderr, "payload not completed\n");
            recycle_buffer(ctx, idx);
            client_ctx.clear_state();
            return 0;
        }

        length -= r.payload_length();

        if (handle_request(ctx, &r, idx, fdidx) < 0) {
            return -1;
        }
        client_ctx.clear_state();
    }
    while (true) {
        if(length == 0){
            break;
        }
        if (length < request::length_size) {
            client_ctx.buf = std::make_unique<unsigned char[]>(BUFFER_SIZE);
            client_ctx.curr_idx = length;
            client_ctx.length = -1;
            memcpy(client_ctx.buf.get(), buf, length);
            recycle_buffer(ctx, idx);
            return 0;
        }
        auto curr_length = *reinterpret_cast<uint32_t *>(buf);

        if (curr_length > BUFFER_SIZE) { // invalid
            fprintf(stderr, "maxium data length\n");
            recycle_buffer(ctx, idx);
            return 0;
        }
        if (curr_length > length) {
            client_ctx.buf = std::make_unique<unsigned char[]>(
                curr_length + request::length_size);
            client_ctx.length = curr_length;
            client_ctx.curr_idx = length;
            memcpy(client_ctx.buf.get(), buf, length);
            recycle_buffer(ctx, idx);
            return 0;
        }
        buf += request::length_size;
        length -= request::length_size;

        request r;
        if (request::parse(buf, buf + length, &r) < 0) {
            fprintf(stderr, "payload not completed\n");
            recycle_buffer(ctx, idx);
            client_ctx.clear_state();
            return 0;
        }
        length -= r.payload_length();

        if (handle_request(ctx, &r, idx, fdidx) < 0) {
            return -1;
        }
        client_ctx.clear_state();
    }
    return 0;
}

int process_cqe_accept(struct ctx *ctx, struct io_uring_cqe *cqe) {
    int ret;
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        ret = add_accept(ctx, 0);
        if (ret)
            return ret;
    }
    if (cqe->res < 0) {
        fprintf(stderr, "accept: %s\n", strerror(abs(cqe->res)));
        exit(1);
    }
    int fdidx = cqe->res;
    ret = add_recv(ctx, fdidx);
    if (ret)
        return 1;

    if (ctx->verbose) {
        sockaddr_in6 addr6;
        socklen_t socklength = sizeof(sockaddr_in6);
        sockaddr_in *addr = (sockaddr_in *)&addr6;
        if (getpeername(fdidx, (sockaddr *)(&addr6), &socklength)) {
            fprintf(stderr, "getpeername failed\n");
        }
        char buff[INET6_ADDRSTRLEN + 1];
        const char *name;
        void *paddr;

        if (ctx->af == AF_INET6)
            paddr = &addr6.sin6_addr;
        else
            paddr = &addr->sin_addr;

        name = inet_ntop(ctx->af, paddr, buff, sizeof(buff));
        if (!name)
            name = "<INVALID>";
        fprintf(stderr, "accepct connection from [%s]:%d\n", name,
                (int)ntohs(addr->sin_port));
    }
    return 0;
}

static int process_cqe(struct ctx *ctx, struct io_uring_cqe *cqe) {
    user_data *ud = (user_data *)&cqe->user_data;
    if (ud->index < BUFFERS)
        return process_cqe_send(ctx, cqe);
    else if (ud->index == BUFFERS + 1)
        return process_cqe_recv(ctx, cqe);
    else
        return process_cqe_accept(ctx, cqe);
}

int main(int argc, char *argv[]) {
    struct ctx ctx;
    int ret;
    int port = -1;
    int opt;
    struct io_uring_cqe *cqes[CQES];
    unsigned int count, i;

    while ((opt = getopt(argc, argv, "6vp:")) != -1) {
        switch (opt) {
        case '6':
            ctx.af = AF_INET6;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'v':
            ctx.verbose = true;
            break;
        default:
            fprintf(stderr,
                    "Usage: %s [-p port] "
                    "[-b log2(BufferSize)] [-6] [-v]\n",
                    argv[0]);
            exit(-1);
        }
    }

    auto sockfd = setup_sock(ctx.af, port);
    if (sockfd < 0)
        return 1;

    if (setup_context(&ctx)) {
        close(sockfd);
        return 1;
    }

    ret = io_uring_register_files(&ctx.ring, &sockfd, 1);
    if (ret) {
        fprintf(stderr, "register files: %s\n", strerror(-ret));
        return -1;
    }

    ret = add_accept(&ctx, 0); // direct fd
    if (ret)
        return 1;

    while (true) {
        ret = io_uring_submit_and_wait(&ctx.ring, 1);
        if (ret == -EINTR)
            continue;
        if (ret < 0) {
            fprintf(stderr, "submit and wait failed %d\n", ret);
            break;
        }

        count = io_uring_peek_batch_cqe(&ctx.ring, &cqes[0], CQES);
        for (i = 0; i < count; i++) {
            ret = process_cqe(&ctx, cqes[i]);
            if (ret)
                goto cleanup;
        }
        io_uring_cq_advance(&ctx.ring, count);
    }

cleanup:
    cleanup_context(&ctx);
    close(sockfd);
    return ret;
}
