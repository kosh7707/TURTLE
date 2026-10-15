#include "transport/channel.hpp"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdexcept>
#include <sys/socket.h>
namespace turtle::transport {
namespace {
IoResult transfer(Channel& channel, bool sending, std::uint8_t* data, std::size_t size) noexcept {
    Observation observation{sending, true, data, size, {}};
    if (channel.observe)
        channel.observe(channel.observer, observation);
    ssize_t count;
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(timespec))]{};
    iovec vector{data, size};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary;
    message.msg_controllen = sizeof ancillary;
    do {
        count = sending ? ::send(channel.fd, data, size, MSG_NOSIGNAL)
                        : ::recvmsg(channel.fd, &message, 0);
    } while (count < 0 && errno == EINTR);
    const int error = count < 0 ? errno : 0;
    IoResult result;
    if (count > 0)
        result = {IoStatus::Ok, static_cast<std::size_t>(count), 0};
    else if (count == 0)
        result = {IoStatus::Closed, 0, 0};
    else if (error == EAGAIN || error == EWOULDBLOCK)
        result = {sending ? IoStatus::WantWrite : IoStatus::WantRead, 0, error};
    else
        result = {IoStatus::Failed, 0, error};
    observation.entering = false;
    observation.result = result;
    if (!sending && count > 0 && !(message.msg_flags & MSG_CTRUNC)) {
        for (auto* c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS &&
                c->cmsg_len >= CMSG_LEN(sizeof(timespec))) {
                timespec stamp{};
                std::memcpy(&stamp, CMSG_DATA(c), sizeof stamp);
                observation.kernel_realtime_ns =
                    static_cast<std::uint64_t>(stamp.tv_sec) * 1000000000ULL + stamp.tv_nsec;
            }
        }
    }
    if (channel.observe)
        channel.observe(channel.observer, observation);
    return result;
}
IoResult send(void* p, const std::uint8_t* data, std::size_t size) noexcept {
    return transfer(*static_cast<Channel*>(p), true, const_cast<std::uint8_t*>(data), size);
}
IoResult recv(void* p, std::uint8_t* data, std::size_t size) noexcept {
    return transfer(*static_cast<Channel*>(p), false, data, size);
}
} // namespace
Io Channel::io() noexcept {
    return {this, send, recv, fd};
}
model::SocketSettings configure(int fd, bool nodelay, int send_buffer, int receive_buffer,
                                bool timestamps) {
    int flags = ::fcntl(fd, F_GETFL);
    int value = nodelay;
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof value) < 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof send_buffer) < 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof receive_buffer) < 0)
        throw std::runtime_error("TCP configuration failed");
    value = timestamps;
    const bool timestamp_option =
        ::setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &value, sizeof value) == 0;
    if (!timestamps && !timestamp_option)
        throw std::runtime_error("cannot disable TCP receive timestamps");
    const auto option = [fd](int level, int name) {
        int observed = 0;
        socklen_t size = sizeof observed;
        if (::getsockopt(fd, level, name, &observed, &size) < 0 || size != sizeof observed)
            throw std::runtime_error("TCP configuration readback failed");
        return observed;
    };
    flags = ::fcntl(fd, F_GETFL);
    model::SocketSettings observed;
    observed.nonblocking = flags >= 0 && (flags & O_NONBLOCK) != 0;
    observed.tcp_nodelay = option(IPPROTO_TCP, TCP_NODELAY) != 0;
    observed.send_buffer = option(SOL_SOCKET, SO_SNDBUF);
    observed.receive_buffer = option(SOL_SOCKET, SO_RCVBUF);
    observed.kernel_timestamps = timestamp_option && option(SOL_SOCKET, SO_TIMESTAMPNS) != 0;
    if (!observed.nonblocking || observed.tcp_nodelay != nodelay || observed.send_buffer <= 0 ||
        observed.receive_buffer <= 0 ||
        (timestamp_option && observed.kernel_timestamps != timestamps))
        throw std::runtime_error("TCP configuration was not applied");
    return observed;
}
} // namespace turtle::transport
