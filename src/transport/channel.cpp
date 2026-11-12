#include "transport/channel.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdexcept>
#include <sys/socket.h>
namespace turtle::transport {
namespace {
IoResult transfer(Channel& channel, bool sending, std::uint8_t* data, std::size_t size) noexcept {
    channel.drain_tx();
    Observation observation{sending, true, data, size, {}};
    observation.batch_id = sending ? channel.batch_id : 0;
    if (channel.observe)
        channel.observe(channel.observer, observation);
    ssize_t count;
    alignas(cmsghdr) char
        ancillary[CMSG_SPACE(sizeof(timespec)) + CMSG_SPACE(sizeof(scm_timestamping))]{};
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
    channel.drain_tx();
    return result;
}
IoResult send(void* p, const std::uint8_t* data, std::size_t size) noexcept {
    auto& channel = *static_cast<Channel*>(p);
    if (channel.holding && !channel.submit_first_write) {
        if (size > channel.output.size() - channel.queued)
            return {IoStatus::Failed, 0, ENOBUFS};
        if (!channel.queued)
            ++channel.batch_id;
        std::memcpy(channel.output.data() + channel.queued, data, size);
        channel.queued += size;
        const IoResult result{IoStatus::Ok, size, 0};
        if (channel.observe)
            channel.observe(channel.observer,
                            {true, false, data, size, result, 0, true, channel.batch_id});
        return result;
    }
    if (!channel.direct_remaining) {
        ++channel.batch_id;
        channel.direct_remaining = size;
    }
    auto result = transfer(channel, true, const_cast<std::uint8_t*>(data), size);
    channel.direct_remaining -= result.bytes;
    if (!channel.direct_remaining)
        channel.submit_first_write = false;
    return result;
}
IoResult recv(void* p, std::uint8_t* data, std::size_t size) noexcept {
    return transfer(*static_cast<Channel*>(p), false, data, size);
}
} // namespace
Io Channel::io() noexcept {
    return {this, send, recv, fd};
}
IoResult Channel::flush() noexcept {
    if (submitted == queued)
        return {IoStatus::Ok, 0, 0};
    auto result = transfer(*this, true, output.data() + submitted, queued - submitted);
    submitted += result.bytes;
    if (submitted == queued)
        submitted = queued = 0;
    return result;
}
model::SocketSettings configure(int fd, bool nodelay, int send_buffer, int receive_buffer,
                                bool timestamps, bool tx_timestamps) {
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
    if (tx_timestamps) {
        // OPT_ID_TCP starts the ID at write_seq, excluding the TCP SYN. Each
        // ee_data is the last byte of a request, not a packet/record identifier.
        constexpr int flags = SOF_TIMESTAMPING_TX_SCHED | SOF_TIMESTAMPING_TX_SOFTWARE |
                              SOF_TIMESTAMPING_TX_ACK | SOF_TIMESTAMPING_SOFTWARE |
                              SOF_TIMESTAMPING_OPT_ID | SOF_TIMESTAMPING_OPT_TSONLY |
                              (1 << 16); // SOF_TIMESTAMPING_OPT_ID_TCP (Linux UAPI)
        if (::setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof flags) == 0)
            observed.kernel_tx_timestamps = option(SOL_SOCKET, SO_TIMESTAMPING) == flags;
        else
            observed.kernel_tx_timestamp_error = errno;
        if (!observed.kernel_tx_timestamps && !observed.kernel_tx_timestamp_error)
            observed.kernel_tx_timestamp_error = EOPNOTSUPP;
    }
    if (!observed.nonblocking || observed.tcp_nodelay != nodelay || observed.send_buffer <= 0 ||
        observed.receive_buffer <= 0 ||
        (timestamp_option && observed.kernel_timestamps != timestamps))
        throw std::runtime_error("TCP configuration was not applied");
    return observed;
}
void Channel::drain_tx() noexcept {
    if (!tx_timestamps)
        return;
    for (;;) {
        alignas(cmsghdr) char ancillary[512]{};
        msghdr message{};
        message.msg_control = ancillary;
        message.msg_controllen = sizeof ancillary;
        const auto count = ::recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                tx_drain_error = errno;
            return;
        }
        if (message.msg_flags & MSG_CTRUNC) {
            tx_drain_error = ENOBUFS;
            continue;
        }
        scm_timestamping stamps{};
        sock_extended_err error{};
        bool have_stamp = false, have_error = false;
        for (auto* c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPING &&
                c->cmsg_len >= CMSG_LEN(sizeof stamps)) {
                std::memcpy(&stamps, CMSG_DATA(c), sizeof stamps);
                have_stamp = true;
            }
            if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVERR &&
                c->cmsg_len >= CMSG_LEN(sizeof error)) {
                std::memcpy(&error, CMSG_DATA(c), sizeof error);
                have_error = true;
            }
        }
        if (!have_stamp || !have_error || error.ee_origin != SO_EE_ORIGIN_TIMESTAMPING ||
            error.ee_errno != ENOMSG || stamps.ts[0].tv_sec <= 0) {
            tx_drain_error = ENOMSG;
            continue;
        }
        model::EventKind kind;
        switch (error.ee_info) {
        case SCM_TSTAMP_SCHED:
            kind = model::EventKind::KernelTxSched;
            break;
        case SCM_TSTAMP_SND:
            kind = model::EventKind::KernelTxSnd;
            break;
        case SCM_TSTAMP_ACK:
            kind = model::EventKind::KernelTxAck;
            break;
        default:
            tx_drain_error = EPROTO;
            continue;
        }
        const auto realtime = static_cast<std::uint64_t>(stamps.ts[0].tv_sec) * 1000000000ULL +
                              static_cast<std::uint64_t>(stamps.ts[0].tv_nsec);
        if (kind == model::EventKind::KernelTxAck)
            tx_acknowledged_end =
                std::max(tx_acknowledged_end, static_cast<std::uint64_t>(error.ee_data) + 1);
        if (observe_tx)
            observe_tx(observer, {kind, realtime, error.ee_data});
    }
}
} // namespace turtle::transport
