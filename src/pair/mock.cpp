#include "mock.hpp"
#include "mock_socket.hpp"
#include <iostream>

namespace {
void exchange(mock::Socket &socket, bool client) {
  struct Counts {
    unsigned sends = 0, reads = 0;
  } counts;
  const auto boundary = socket.boundary();
  boundary.set_hooks(boundary.transport,
                     {&counts,
                      [](void *p) { ++static_cast<Counts *>(p)->sends; },
                      [](void *p) { ++static_cast<Counts *>(p)->reads; }});
  if (client) {
    socket.send(mock::client_hello);
    socket.expect(mock::server_flight);
    socket.send(mock::client_finished);
  } else {
    socket.expect(mock::client_hello);
    socket.send(mock::server_flight);
    socket.expect(mock::client_finished);
  }
  boundary.set_hooks(boundary.transport, {});
  std::cout << "mock " << (client ? "client" : "server")
            << ": S0 matched (not TLS); before_send=" << counts.sends
            << " after_receive=" << counts.reads << '\n';
}
} // namespace

void mock_role(bool client, std::uint16_t port) {
  auto addr = mock::loopback(port);
  auto *address = reinterpret_cast<sockaddr *>(&addr);
  mock::Socket socket;
  if (client) {
    mock::checked(::connect(socket.fd(), address, sizeof(addr)), "connect");
    exchange(socket, true);
    return;
  }

  mock::checked(::bind(socket.fd(), address, sizeof(addr)), "bind");
  mock::checked(::listen(socket.fd(), 1), "listen");
  socklen_t length = sizeof(addr);
  mock::checked(::getsockname(socket.fd(), address, &length), "getsockname");
  std::cout << "READY " << ntohs(addr.sin_port) << std::endl;
  int fd;
  do {
    fd = ::accept(socket.fd(), nullptr, nullptr);
  } while (fd < 0 && errno == EINTR);
  mock::Socket peer(mock::checked(fd, "accept"));
  exchange(peer, false);
}
