#pragma once
#include <array>
#include <openssl/ssl.h>
#include <turtle/adapter.hpp>

namespace turtle::openssl_adapter {
struct State final : Context {
    Role role;
    const TlsConfig& config;
    const HostServices& services;
    SSL_CTX* ssl = nullptr;
    BIO_METHOD* method = nullptr;
    bool allocator_installed = false;
    State(Role r, const TlsConfig& c, const HostServices& s) : role(r), config(c), services(s) {}
    ~State() override;
};
struct Session final : Connection {
    State& state;
    const Io& io;
    SSL* ssl = nullptr;
    bool hrr = false;
    bool sink_failed = false;
    std::array<char, 256> error{};
    Session(State& s, const Io& i) : state(s), io(i) {}
    ~Session() override;
};
} // namespace turtle::openssl_adapter
