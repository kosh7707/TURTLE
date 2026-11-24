#include "chat.hpp"
#include "server.hpp"

#include <csignal>
#include <cstdio>
#include <iostream>

int main(int argc, char** argv) try {
    std::signal(SIGPIPE, SIG_IGN);
    const auto port = port_argument(argc, argv, true);
    auto ctx = server::configure_tls();
    auto listener = server::listen_tcp(port);
    auto peer = server::accept_tcp(listener);
    auto ssl = attach_socket_bio(ctx, peer);
    server::handshake(ssl.get());
    run_chat(ssl.get());
    return 0;
} catch (const std::exception& e) {
    std::cerr << "chat_server: " << e.what() << '\n';
    ERR_print_errors_fp(stderr);
    return 1;
}
