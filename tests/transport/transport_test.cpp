#include "control/control.hpp"
#include "transport/channel.hpp"
#include "transport/tcp.hpp"
#include <array>
#include <climits>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
void require(bool value) {
    if (!value)
        throw std::runtime_error("transport assertion failed");
}
struct Observation {
    std::size_t entered = 0, returned = 0, bytes = 0;
};
void observe(void* p, const turtle::transport::Observation& event) noexcept {
    auto& state = *static_cast<Observation*>(p);
    if (event.entering)
        ++state.entered;
    else {
        ++state.returned;
        state.bytes += event.result.bytes;
    }
}
int socket_option(int fd, int level, int option) {
    int value = 0;
    socklen_t size = sizeof value;
    require(::getsockopt(fd, level, option, &value, &size) == 0);
    require(size == sizeof value);
    return value;
}
void require_settings_match(int fd, const turtle::model::SocketSettings& settings) {
    const int flags = ::fcntl(fd, F_GETFL);
    require(flags >= 0);
    require(settings.nonblocking == static_cast<bool>(flags & O_NONBLOCK));
    require(settings.tcp_nodelay == static_cast<bool>(socket_option(fd, IPPROTO_TCP, TCP_NODELAY)));
    require(settings.send_buffer == socket_option(fd, SOL_SOCKET, SO_SNDBUF));
    require(settings.receive_buffer == socket_option(fd, SOL_SOCKET, SO_RCVBUF));
    require(settings.kernel_timestamps ==
            static_cast<bool>(socket_option(fd, SOL_SOCKET, SO_TIMESTAMPNS)));
}
int main() {
    try {
        auto listener = turtle::tcp::listen_loopback();
        auto client = turtle::tcp::connect_loopback(listener.port);
        auto server = turtle::tcp::accept_one(listener.fd);
        ::close(listener.fd);
        require(turtle::tcp::check_ready(client).empty());
        require(turtle::tcp::check_ready(server).empty());
        const auto small = turtle::transport::configure(client, true, 1, 1, true);
        require_settings_match(client, small);
        require(small.nonblocking && small.tcp_nodelay && small.send_buffer > 0 &&
                small.receive_buffer > 0 && small.kernel_timestamps);
        require(small.send_buffer != 1 && small.receive_buffer != 1);

        const auto large =
            turtle::transport::configure(server, false, INT_MAX, INT_MAX, false);
        require_settings_match(server, large);
        require(large.nonblocking && !large.tcp_nodelay && large.send_buffer > 0 &&
                large.receive_buffer > 0 && !large.kernel_timestamps);
        require(large.send_buffer != INT_MAX && large.receive_buffer != INT_MAX);

        const auto timestamps_off = turtle::transport::configure(client, false, 65536, 65536, false);
        require_settings_match(client, timestamps_off);
        require(!timestamps_off.tcp_nodelay && !timestamps_off.kernel_timestamps);
        Observation state;
        turtle::transport::Channel send{client}, recv{server, &state, observe};
        auto sender = send.io();
        auto receiver = recv.io();
        std::array<std::uint8_t, 4> data{1, 2, 3, 4}, received{};
        auto empty = receiver.recv(receiver.context, received.data(), received.size());
        require(empty.status == turtle::IoStatus::WantRead && empty.bytes == 0);
        auto sent = sender.send(sender.context, data.data(), data.size());
        require(sent.status == turtle::IoStatus::Ok && sent.bytes == 4);
        turtle::control::wait(server, false,
                              std::chrono::steady_clock::now() + std::chrono::seconds(1));
        auto got = receiver.recv(receiver.context, received.data(), received.size());
        require(got.status == turtle::IoStatus::Ok && got.bytes == 4 && data == received);
        require(state.entered == 2 && state.returned == 2 && state.bytes == 4);
        ::close(client);
        ::close(server);
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
