#include "chat.hpp"
#include "client.hpp"

#include <csignal>
#include <cstdio>
#include <iostream>

int main(int argc, char** argv) try {
    std::signal(SIGPIPE, SIG_IGN);
    const auto port = port_argument(argc, argv, false);
    auto ctx = client::configure_tls();
    auto peer = client::connect_tcp(port);
    auto ssl = attach_socket_bio(ctx, peer);
    client::handshake(ssl.get());
    run_chat(ssl.get());
    return 0;
} catch (const std::exception& e) {
    std::cerr << "chat_client: " << e.what() << '\n';
    ERR_print_errors_fp(stderr);
    return 1;
}
