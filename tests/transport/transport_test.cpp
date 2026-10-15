#include "control/control.hpp"
#include "transport/channel.hpp"
#include "transport/tcp.hpp"
#include <array>
#include <climits>
#include <cstddef>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <linux/tcp.h>
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
        bool invalid_address_rejected = false;
        try {
            (void)turtle::tcp::listen_ipv4("localhost", 0);
        } catch (const std::invalid_argument&) {
            invalid_address_rejected = true;
        }
        require(invalid_address_rejected);

        auto listener = turtle::tcp::listen_ipv4("127.0.0.1", 0);
        const auto listener_endpoint = turtle::tcp::local_endpoint(listener.fd);
        require(listener_endpoint.address == "127.0.0.1");
        require(listener_endpoint.port == listener.port && listener.port != 0);
        auto client = turtle::tcp::connect_ipv4(
            "127.0.0.1", {listener_endpoint.address, listener_endpoint.port});
        auto server = turtle::tcp::accept_one(listener.fd);
        ::close(listener.fd);
        const auto client_local = turtle::tcp::local_endpoint(client);
        const auto client_peer = turtle::tcp::peer_endpoint(client);
        const auto server_local = turtle::tcp::local_endpoint(server);
        const auto server_peer = turtle::tcp::peer_endpoint(server);
        require(client_local.address == "127.0.0.1" && client_local.port != 0);
        require(client_peer.address == listener_endpoint.address &&
                client_peer.port == listener_endpoint.port);
        require(server_local.address == listener_endpoint.address &&
                server_local.port == listener_endpoint.port);
        require(server_peer.address == client_local.address && server_peer.port == client_local.port);
        require(turtle::tcp::check_ready(client).empty());
        require(turtle::tcp::check_ready(server).empty());

        const auto tcp_start = turtle::tcp::read_tcp_info(client);
        require(tcp_start.structure_bytes > 0);
#define REQUIRE_TCP_FIELD(field, kernel_field)                                                   \
    require(tcp_start.field.has_value() ==                                                        \
            (tcp_start.structure_bytes >=                                                         \
             offsetof(tcp_info, kernel_field) + sizeof(decltype(tcp_info{}.kernel_field))))
        REQUIRE_TCP_FIELD(state, tcpi_state);
        REQUIRE_TCP_FIELD(retransmits, tcpi_retransmits);
        REQUIRE_TCP_FIELD(retrans, tcpi_retrans);
        REQUIRE_TCP_FIELD(total_retrans, tcpi_total_retrans);
        REQUIRE_TCP_FIELD(unacked, tcpi_unacked);
        REQUIRE_TCP_FIELD(lost, tcpi_lost);
        REQUIRE_TCP_FIELD(snd_mss, tcpi_snd_mss);
        REQUIRE_TCP_FIELD(rcv_mss, tcpi_rcv_mss);
        REQUIRE_TCP_FIELD(segs_out, tcpi_segs_out);
        REQUIRE_TCP_FIELD(segs_in, tcpi_segs_in);
        REQUIRE_TCP_FIELD(data_segs_out, tcpi_data_segs_out);
        REQUIRE_TCP_FIELD(data_segs_in, tcpi_data_segs_in);
        REQUIRE_TCP_FIELD(bytes_acked, tcpi_bytes_acked);
        REQUIRE_TCP_FIELD(bytes_received, tcpi_bytes_received);
#undef REQUIRE_TCP_FIELD
        require(tcp_start.state.has_value() && *tcp_start.state == 1);
        const auto unavailable = turtle::tcp::read_tcp_info(-1);
        require(unavailable.structure_bytes == 0 && !unavailable.state.has_value() &&
                !unavailable.note.empty());
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
        const auto tcp_end = turtle::tcp::read_tcp_info(server);
        require(tcp_end.structure_bytes > 0 && tcp_end.state.has_value());
        const auto client_end = turtle::tcp::read_tcp_info(client);
        if (tcp_start.segs_out && client_end.segs_out)
            require(*client_end.segs_out >= *tcp_start.segs_out);
        if (tcp_end.bytes_received)
            require(*tcp_end.bytes_received >= data.size());
        ::close(client);
        ::close(server);

        // Preserve the original loopback convenience path alongside the
        // namespace-aware numeric-address path.
        auto loopback_listener = turtle::tcp::listen_loopback();
        auto loopback_client = turtle::tcp::connect_loopback(loopback_listener.port);
        auto loopback_server = turtle::tcp::accept_one(loopback_listener.fd);
        require(turtle::tcp::check_ready(loopback_client).empty());
        require(turtle::tcp::check_ready(loopback_server).empty());
        ::close(loopback_listener.fd);
        ::close(loopback_client);
        ::close(loopback_server);
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
