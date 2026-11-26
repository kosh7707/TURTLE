#include <turtle/implementation.hpp>

#include <cstdio>

int main() {
    const turtle_tls_config config{};
    const turtle_transport_hooks hooks{};
    auto *tls = turtle_tls_setup(&config, -1);
    if (tls != nullptr) {
        turtle_tls_free(tls);
        std::fputs("starter unexpectedly established a TLS context\n", stderr);
        return 1;
    }
    turtle_tls_free(nullptr);
    unsigned char byte = 0;
    if (turtle_tls_set_hooks(nullptr, &hooks) != TURTLE_TLS_UNSUPPORTED ||
        turtle_tls_connect(nullptr) != TURTLE_TLS_UNSUPPORTED ||
        turtle_tls_accept(nullptr, &byte, 1) != TURTLE_TLS_UNSUPPORTED ||
        turtle_app_send(nullptr, &byte, 1) >= 0 || turtle_app_recv(nullptr, &byte, 1) >= 0) {
        std::fputs("starter unexpectedly enabled TLS or application I/O\n", stderr);
        return 1;
    }
}
