#include "transport/tcp.hpp"
#include "transport/channel.hpp"
#include "control/control.hpp"
#include <unistd.h>
#include <array>
#include <stdexcept>
#include <iostream>
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
int main() {
    try {
        auto listener = turtle::tcp::listen_loopback();
        auto client = turtle::tcp::connect_loopback(listener.port);
        auto server = turtle::tcp::accept_one(listener.fd);
        ::close(listener.fd);
        require(turtle::tcp::check_ready(client).empty());
        require(turtle::tcp::check_ready(server).empty());
        turtle::transport::configure(client, true, 65536, 65536, false);
        turtle::transport::configure(server, true, 65536, 65536, true);
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
