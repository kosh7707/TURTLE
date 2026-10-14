#pragma once

#include <turtle/adapter.hpp>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <array>
#include <cstdint>

namespace turtle::mbedtls_adapter {

struct MbedContext final : Context {
    MbedContext(Role selected_role, const TlsConfig& selected_config,
                const HostServices& selected_services) noexcept;
    ~MbedContext() override;

    Role role;
    const TlsConfig* config;
    const HostServices* services;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_config ssl_config;
    mbedtls_x509_crt ca;
    mbedtls_x509_crt own_certificate;
    mbedtls_pk_context own_key;
    std::array<int, 2> ciphersuites{MBEDTLS_TLS1_3_AES_128_GCM_SHA256, 0};
    std::array<std::uint16_t, 2> groups{MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, 0};
    std::array<std::uint16_t, 2> signature_algorithms{
        MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256, MBEDTLS_TLS1_3_SIG_NONE};
    bool psa_initialized = false;
    bool allocator_installed = false;
};

struct MbedConnection final : Connection {
    MbedConnection(MbedContext& selected_context, const Io& selected_io) noexcept;
    ~MbedConnection() override;

    void set_error(int code) noexcept;
    void set_error(const char* text) noexcept;

    MbedContext& context;
    Io io;
    mbedtls_ssl_context ssl;
    std::array<char, 256> error_text{};
    int last_error = 0;
    bool key_log_failed = false;
    bool handshake_done = false;
};

}  // namespace turtle::mbedtls_adapter

