#pragma once

#include <turtle/adapter.hpp>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <string>

namespace turtle::wolfssl_adapter {

struct WolfContext final : Context {
    Role role;
    TlsConfig config;
    HostServices services;
    WOLFSSL_CTX* ssl_context = nullptr;
    std::string setup_error;
    bool library_initialized = false;

    WolfContext(Role value_role, const TlsConfig& value_config,
                const HostServices& value_services)
        : role(value_role), config(value_config), services(value_services) {}
};

struct WolfConnection final : Connection {
    WolfContext* context;
    Io io;
    WOLFSSL* ssl = nullptr;
    std::string last_error;
    bool handshake_done = false;

    WolfConnection(WolfContext* value_context, const Io& value_io)
        : context(value_context), io(value_io) {}
};

}  // namespace turtle::wolfssl_adapter

