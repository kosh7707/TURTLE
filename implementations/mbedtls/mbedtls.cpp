#include "adapter.hpp"

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/psa_util.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/version.h>
#include <psa/crypto.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <vector>

namespace turtle::mbedtls_adapter {

MbedContext::MbedContext(Role selected_role, const TlsConfig& selected_config,
                         const HostServices& selected_services) noexcept
    : role(selected_role), config(&selected_config), services(&selected_services) {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_config_init(&ssl_config);
    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crt_init(&own_certificate);
    mbedtls_pk_init(&own_key);
}

MbedContext::~MbedContext() {
    mbedtls_pk_free(&own_key);
    mbedtls_x509_crt_free(&own_certificate);
    mbedtls_x509_crt_free(&ca);
    mbedtls_ssl_config_free(&ssl_config);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    if (psa_initialized) {
        mbedtls_psa_crypto_free();
    }
}

MbedConnection::MbedConnection(MbedContext& selected_context, const Io& selected_io) noexcept
    : context(selected_context), io(selected_io) {
    mbedtls_ssl_init(&ssl);
    error_text[0] = '\0';
}

MbedConnection::~MbedConnection() { mbedtls_ssl_free(&ssl); }

void MbedConnection::set_error(int code) noexcept {
    last_error = code;
    mbedtls_strerror(code, error_text.data(), error_text.size());
}

void MbedConnection::set_error(const char* text) noexcept {
    last_error = -1;
    const std::size_t length = std::min(std::strlen(text), error_text.size() - 1);
    std::memcpy(error_text.data(), text, length);
    error_text[length] = '\0';
}

}  // namespace turtle::mbedtls_adapter

namespace {

using turtle::mbedtls_adapter::MbedConnection;
using turtle::mbedtls_adapter::MbedContext;

constexpr char kLibraryName[] = "Mbed TLS";
constexpr char kCipher[] = "TLS_AES_128_GCM_SHA256";
constexpr char kGroup[] = "secp256r1";
constexpr char kSignature[] = "ecdsa_secp256r1_sha256";
constexpr char kTls13[] = "TLS1.3";
constexpr char kNoError[] = "";

bool supported_config(const turtle::Role role, const turtle::TlsConfig& config,
                      const std::span<const std::uint8_t> saved) noexcept {
    if (!saved.empty() || config.cipher != kCipher || config.group != kGroup ||
        config.signature != kSignature || !config.framework_io || config.tickets != 0 ||
        config.record_size_limit != 0 || config.certificate_compression ||
        !config.compatibility_ccs || config.ca_file.empty()) {
        return false;
    }
    if (role == turtle::Role::Server) {
        return !config.server_certificate.empty() && !config.server_key.empty();
    }
    if (config.server_name.empty()) {
        return false;
    }
    return !config.mutual_auth ||
           (!config.client_certificate.empty() && !config.client_key.empty());
}

bool is_p256_ecdsa_key(const mbedtls_pk_context& key) noexcept {
    return mbedtls_pk_can_do(&key, MBEDTLS_PK_ECDSA) != 0 &&
           mbedtls_pk_get_bitlen(&key) == 256;
}

int configure_credentials(MbedContext& context) noexcept {
    const auto& config = *context.config;
    int result = mbedtls_x509_crt_parse_file(&context.ca, config.ca_file.c_str());
    if (result != 0) {
        return result;
    }
    mbedtls_ssl_conf_ca_chain(&context.ssl_config, &context.ca, nullptr);

    const bool needs_own_certificate = context.role == turtle::Role::Server || config.mutual_auth;
    if (!needs_own_certificate) {
        return 0;
    }
    const std::string& certificate = context.role == turtle::Role::Server
                                         ? config.server_certificate
                                         : config.client_certificate;
    const std::string& key =
        context.role == turtle::Role::Server ? config.server_key : config.client_key;
    result = mbedtls_x509_crt_parse_file(&context.own_certificate, certificate.c_str());
    if (result != 0) {
        return result;
    }
    result = mbedtls_pk_parse_keyfile(&context.own_key, key.c_str(), nullptr,
                                      mbedtls_ctr_drbg_random, &context.drbg);
    if (result != 0) {
        return result;
    }
    if (!is_p256_ecdsa_key(context.own_key) ||
        !is_p256_ecdsa_key(context.own_certificate.pk)) {
        return MBEDTLS_ERR_SSL_BAD_CONFIG;
    }
    return mbedtls_ssl_conf_own_cert(&context.ssl_config, &context.own_certificate,
                                     &context.own_key);
}

int send_callback(void* opaque, const unsigned char* buffer, std::size_t size) {
    auto& connection = *static_cast<MbedConnection*>(opaque);
    if (connection.io.send == nullptr ||
        size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    const turtle::IoResult result = connection.io.send(connection.io.context, buffer, size);
    switch (result.status) {
        case turtle::IoStatus::Ok:
            if (result.bytes == 0 || result.bytes > size ||
                result.bytes > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                return MBEDTLS_ERR_NET_SEND_FAILED;
            }
            return static_cast<int>(result.bytes);
        case turtle::IoStatus::WantRead:
            return MBEDTLS_ERR_SSL_WANT_READ;
        case turtle::IoStatus::WantWrite:
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        case turtle::IoStatus::Closed:
            return MBEDTLS_ERR_NET_CONN_RESET;
        case turtle::IoStatus::Failed:
            return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return MBEDTLS_ERR_NET_SEND_FAILED;
}

int recv_callback(void* opaque, unsigned char* buffer, std::size_t size) {
    auto& connection = *static_cast<MbedConnection*>(opaque);
    if (connection.io.recv == nullptr ||
        size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    const turtle::IoResult result = connection.io.recv(connection.io.context, buffer, size);
    switch (result.status) {
        case turtle::IoStatus::Ok:
            if (result.bytes > size ||
                result.bytes > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
                return MBEDTLS_ERR_NET_RECV_FAILED;
            }
            return static_cast<int>(result.bytes);
        case turtle::IoStatus::WantRead:
            return MBEDTLS_ERR_SSL_WANT_READ;
        case turtle::IoStatus::WantWrite:
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        case turtle::IoStatus::Closed:
            return 0;
        case turtle::IoStatus::Failed:
            return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return MBEDTLS_ERR_NET_RECV_FAILED;
}

char hexadecimal_digit(unsigned value) noexcept {
    return static_cast<char>(value < 10 ? '0' + value : 'a' + (value - 10));
}

const char* key_log_label(mbedtls_ssl_key_export_type type) noexcept {
    switch (type) {
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_EARLY_SECRET:
            return "CLIENT_EARLY_TRAFFIC_SECRET";
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_EARLY_EXPORTER_SECRET:
            return "EARLY_EXPORTER_SECRET";
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
            return "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET:
            return "SERVER_HANDSHAKE_TRAFFIC_SECRET";
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET:
            return "CLIENT_TRAFFIC_SECRET_0";
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET:
            return "SERVER_TRAFFIC_SECRET_0";
        case MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET:
            return nullptr;
    }
    return nullptr;
}

void export_keys_callback(void* opaque, mbedtls_ssl_key_export_type type,
                          const unsigned char* secret, std::size_t secret_size,
                          const unsigned char client_random[32], const unsigned char[32],
                          mbedtls_tls_prf_types) {
    auto& connection = *static_cast<MbedConnection*>(opaque);
    const char* label = key_log_label(type);
    const auto& sink = connection.context.services->key_log;
    if (label == nullptr || sink.append == nullptr) {
        return;
    }

    // A TLS 1.3 SHA-256 secret produces at most 32 bytes. Keep the measured
    // callback allocation-free and reject unexpected sizes rather than truncate.
    std::array<char, 192> line{};
    const std::size_t label_size = std::strlen(label);
    const std::size_t required = label_size + 1 + 64 + 1 + secret_size * 2 + 1;
    if (required > line.size()) {
        connection.key_log_failed = true;
        return;
    }
    std::size_t offset = 0;
    std::memcpy(line.data(), label, label_size);
    offset += label_size;
    line[offset++] = ' ';
    for (std::size_t i = 0; i < 32; ++i) {
        line[offset++] = hexadecimal_digit(client_random[i] >> 4);
        line[offset++] = hexadecimal_digit(client_random[i] & 0x0f);
    }
    line[offset++] = ' ';
    for (std::size_t i = 0; i < secret_size; ++i) {
        line[offset++] = hexadecimal_digit(secret[i] >> 4);
        line[offset++] = hexadecimal_digit(secret[i] & 0x0f);
    }
    line[offset++] = '\n';
    if (!sink.append(sink.context, line.data(), offset)) {
        connection.key_log_failed = true;
    }
}

const char* name() noexcept { return kLibraryName; }

turtle::Declaration declaration(const turtle::Context* base) {
    turtle::Declaration result;
    result.library = kLibraryName;
    result.version = MBEDTLS_VERSION_STRING_FULL;
    result.build_options =
        "TLS 1.3; callback I/O; ECDSA P-256; AES-128-GCM; negotiated group and "
        "signature inferred from single-item allow-lists; HelloRetryRequest not observed";
    result.context_description = "No resumable context; tickets are disabled";
    result.callback_io = true;
    result.allocator_hooks = false;
    result.key_log = true;
    result.plaintext_hook = false;
    result.extra_threads = false;
    result.context_serialization = false;
    result.is_mock = false;
    result.memory_note =
        "Host allocator hooks are not implemented in this build; Mbed TLS exposes process-global hooks";
    if (base == nullptr) {
        return result;
    }
    return result;
}

turtle::Context* setup(turtle::Role role, const turtle::TlsConfig& config,
                       const turtle::HostServices& services,
                       std::span<const std::uint8_t> saved) {
    if (!supported_config(role, config, saved)) {
        return nullptr;
    }
    auto* context = new (std::nothrow) MbedContext(role, config, services);
    if (context == nullptr) {
        return nullptr;
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        delete context;
        return nullptr;
    }
    context->psa_initialized = true;
    constexpr unsigned char personalization[] = "TURTLE Mbed TLS adapter";
    int result = mbedtls_ctr_drbg_seed(&context->drbg, mbedtls_entropy_func, &context->entropy,
                                       personalization, sizeof(personalization) - 1);
    if (result != 0) {
        delete context;
        return nullptr;
    }

    const int endpoint = role == turtle::Role::Client ? MBEDTLS_SSL_IS_CLIENT
                                                       : MBEDTLS_SSL_IS_SERVER;
    result = mbedtls_ssl_config_defaults(&context->ssl_config, endpoint,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0) {
        delete context;
        return nullptr;
    }
    mbedtls_ssl_conf_rng(&context->ssl_config, mbedtls_ctr_drbg_random, &context->drbg);
    mbedtls_ssl_conf_min_tls_version(&context->ssl_config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&context->ssl_config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_ciphersuites(&context->ssl_config, context->ciphersuites.data());
    mbedtls_ssl_conf_groups(&context->ssl_config, context->groups.data());
    mbedtls_ssl_conf_sig_algs(&context->ssl_config, context->signature_algorithms.data());
    mbedtls_ssl_conf_tls13_key_exchange_modes(
        &context->ssl_config, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
    if (role == turtle::Role::Client) {
        mbedtls_ssl_conf_authmode(&context->ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_session_tickets(&context->ssl_config,
                                         MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
        mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
            &context->ssl_config, MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_DISABLED);
    } else {
        mbedtls_ssl_conf_authmode(&context->ssl_config,
                                  config.mutual_auth ? MBEDTLS_SSL_VERIFY_REQUIRED
                                                     : MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_new_session_tickets(&context->ssl_config, 0);
    }
    result = configure_credentials(*context);
    if (result != 0) {
        delete context;
        return nullptr;
    }
    return context;
}

turtle::Connection* open(turtle::Context* base, const turtle::Io& io) {
    if (base == nullptr || io.send == nullptr || io.recv == nullptr) {
        return nullptr;
    }
    auto& context = *static_cast<MbedContext*>(base);
    auto* connection = new (std::nothrow) MbedConnection(context, io);
    if (connection == nullptr) {
        return nullptr;
    }
    int result = mbedtls_ssl_setup(&connection->ssl, &context.ssl_config);
    if (result == 0 && context.role == turtle::Role::Client) {
        result = mbedtls_ssl_set_hostname(&connection->ssl, context.config->server_name.c_str());
    }
    if (result != 0) {
        delete connection;
        return nullptr;
    }
    mbedtls_ssl_set_bio(&connection->ssl, connection, send_callback, recv_callback, nullptr);
    mbedtls_ssl_set_export_keys_cb(&connection->ssl, export_keys_callback, connection);
    return connection;
}

turtle::Step translate_result(MbedConnection& connection, int result) noexcept {
    if (connection.key_log_failed) {
        connection.set_error("key log sink rejected exported TLS secrets");
        return turtle::Step::Failed;
    }
    if (result == MBEDTLS_ERR_SSL_WANT_READ) {
        return turtle::Step::WantRead;
    }
    if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return turtle::Step::WantWrite;
    }
    if (result < 0) {
        connection.set_error(result);
        return turtle::Step::Failed;
    }
    return turtle::Step::Done;
}

turtle::Step handshake_step(turtle::Connection* base) {
    if (base == nullptr) {
        return turtle::Step::Failed;
    }
    auto& connection = *static_cast<MbedConnection*>(base);
    while (!mbedtls_ssl_is_handshake_over(&connection.ssl)) {
        const int result = mbedtls_ssl_handshake_step(&connection.ssl);
        if (connection.key_log_failed) {
            connection.set_error("key log sink rejected exported TLS secrets");
            return turtle::Step::Failed;
        }
        if (result == MBEDTLS_ERR_SSL_WANT_READ) {
            return turtle::Step::WantRead;
        }
        if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return turtle::Step::WantWrite;
        }
        if (result < 0) {
            connection.set_error(result);
            return turtle::Step::Failed;
        }
    }
    connection.handshake_done = true;
    return turtle::Step::Done;
}

turtle::Verification peer_verification(turtle::Connection* base) {
    if (base == nullptr) {
        return turtle::Verification::Failed;
    }
    const auto& connection = *static_cast<const MbedConnection*>(base);
    const bool verification_applies = connection.context.role == turtle::Role::Client ||
                                      connection.context.config->mutual_auth;
    if (!verification_applies) {
        return turtle::Verification::NotApplicable;
    }
    if (!connection.handshake_done || mbedtls_ssl_get_peer_cert(&connection.ssl) == nullptr ||
        mbedtls_ssl_get_verify_result(&connection.ssl) != 0) {
        return turtle::Verification::Failed;
    }
    return turtle::Verification::Passed;
}

turtle::Negotiated negotiated(turtle::Connection* base) {
    turtle::Negotiated result;
    if (base == nullptr) {
        return result;
    }
    const auto& connection = *static_cast<const MbedConnection*>(base);
    if (!connection.handshake_done) {
        return result;
    }
    if (mbedtls_ssl_get_version_number(&connection.ssl) == MBEDTLS_SSL_VERSION_TLS1_3) {
        result.version = kTls13;
    }
    if (mbedtls_ssl_get_ciphersuite_id_from_ssl(&connection.ssl) ==
        MBEDTLS_TLS1_3_AES_128_GCM_SHA256) {
        result.cipher = kCipher;
    }
    // Mbed TLS 3.6 does not expose these negotiated values. They are inferred
    // from the only group and signature scheme this adapter permits.
    result.group = kGroup;
    result.signature = kSignature;
    result.resumed = false;
    result.hello_retry_request = false;
    result.peer_certificate_present = mbedtls_ssl_get_peer_cert(&connection.ssl) != nullptr;
    return result;
}

turtle::AppResult app_send(turtle::Connection* base, const std::uint8_t* data,
                           std::size_t size) {
    if (base == nullptr || data == nullptr || size == 0) {
        return {};
    }
    auto& connection = *static_cast<MbedConnection*>(base);
    const int result = mbedtls_ssl_write(&connection.ssl, data, size);
    const turtle::Step step = translate_result(connection, result);
    return {step, result > 0 ? static_cast<std::size_t>(result) : 0};
}

turtle::AppResult app_recv(turtle::Connection* base, std::uint8_t* data, std::size_t size) {
    if (base == nullptr || data == nullptr || size == 0) {
        return {};
    }
    auto& connection = *static_cast<MbedConnection*>(base);
    const int result = mbedtls_ssl_read(&connection.ssl, data, size);
    if (result == 0 || result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        connection.set_error("peer closed before application data completed");
        return {};
    }
    const turtle::Step step = translate_result(connection, result);
    return {step, result > 0 ? static_cast<std::size_t>(result) : 0};
}

const char* error(const turtle::Connection* base) noexcept {
    if (base == nullptr) {
        return "null Mbed TLS connection";
    }
    const auto& connection = *static_cast<const MbedConnection*>(base);
    return connection.last_error == 0 ? kNoError : connection.error_text.data();
}

void close(turtle::Connection* connection) noexcept {
    delete static_cast<MbedConnection*>(connection);
}

std::vector<std::uint8_t> save(turtle::Context*) { return {}; }

void teardown(turtle::Context* context) noexcept { delete static_cast<MbedContext*>(context); }

}  // namespace

extern "C" turtle::ImplementationApi turtle_adapter_v1() {
    return {turtle::adapter_api_version,
            name,
            declaration,
            setup,
            open,
            handshake_step,
            peer_verification,
            negotiated,
            app_send,
            app_recv,
            error,
            close,
            save,
            teardown};
}
