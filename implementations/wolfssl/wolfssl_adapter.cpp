#include "adapter.hpp"

#include <wolfssl/error-ssl.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfio.h>

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

using turtle::Allocator;
using turtle::AppResult;
using turtle::Connection;
using turtle::Context;
using turtle::Declaration;
using turtle::HostServices;
using turtle::Io;
using turtle::IoStatus;
using turtle::Negotiated;
using turtle::Role;
using turtle::Scenario;
using turtle::SendPolicy;
using turtle::Step;
using turtle::TlsConfig;
using turtle::TraceOperation;
using turtle::Verification;
using turtle::wolfssl_adapter::WolfConnection;
using turtle::wolfssl_adapter::WolfContext;

constexpr const char* kWolfSslVersion = LIBWOLFSSL_VERSION_STRING;
constexpr const char* kCipher = "TLS_AES_128_GCM_SHA256";
constexpr const char* kWolfCipher = "TLS13-AES128-GCM-SHA256";
#ifdef TURTLE_MLKEM
constexpr const char* kGroup = "ML_KEM_768";
constexpr int kWolfGroup = WOLFSSL_ML_KEM_768;
#else
constexpr const char* kGroup = "secp256r1";
constexpr int kWolfGroup = WOLFSSL_ECC_SECP256R1;
#endif
constexpr const char* kSignature = "ecdsa_secp256r1_sha256";

// wolfSSL's allocator registration has no user argument. Each role runs in a
// fresh process, so a non-owning thread-local bridge safely scopes callbacks to
// the one memory-mode context in that role process.
thread_local const Allocator* active_allocator = nullptr;

void* host_allocate(std::size_t size) {
    return active_allocator == nullptr
               ? nullptr
               : active_allocator->allocate(active_allocator->context, size);
}

void host_deallocate(void* pointer) {
    if (active_allocator != nullptr) {
        active_allocator->deallocate(active_allocator->context, pointer);
    }
}

void* host_reallocate(void* pointer, std::size_t size) {
    return active_allocator == nullptr
               ? nullptr
               : active_allocator->reallocate(active_allocator->context, pointer, size);
}

void set_wolf_error(WolfConnection& connection, const char* operation, int error) {
    char detail[WOLFSSL_MAX_ERROR_SZ] = {};
    wolfSSL_ERR_error_string_n(static_cast<unsigned long>(error), detail, sizeof(detail));
    connection.last_error =
        std::string(operation) + ": " + detail + " (" + std::to_string(error) + ")";
}

void set_setup_error(WolfContext& context, const char* operation) {
    const unsigned long error = wolfSSL_ERR_get_error();
    char detail[WOLFSSL_MAX_ERROR_SZ] = {};
    wolfSSL_ERR_error_string_n(error, detail, sizeof(detail));
    context.setup_error =
        std::string(operation) + ": " + detail + " (" + std::to_string(error) + ")";
}

int io_receive(WOLFSSL*, char* output, int size, void* opaque) {
    auto* connection = static_cast<WolfConnection*>(opaque);
    if (connection == nullptr || output == nullptr || size <= 0 || connection->io.recv == nullptr) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    const auto result =
        connection->io.recv(connection->io.context, reinterpret_cast<std::uint8_t*>(output),
                            static_cast<std::size_t>(size));
    switch (result.status) {
    case IoStatus::Ok:
        if (result.bytes == 0 || result.bytes > static_cast<std::size_t>(size) ||
            result.bytes > static_cast<std::size_t>(INT_MAX)) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        return static_cast<int>(result.bytes);
    case IoStatus::WantRead:
    case IoStatus::WantWrite:
        return WOLFSSL_CBIO_ERR_WANT_READ;
    case IoStatus::Closed:
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    case IoStatus::Failed:
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return WOLFSSL_CBIO_ERR_GENERAL;
}

int io_send(WOLFSSL*, char* input, int size, void* opaque) {
    auto* connection = static_cast<WolfConnection*>(opaque);
    if (connection == nullptr || input == nullptr || size <= 0 || connection->io.send == nullptr) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    const auto result =
        connection->io.send(connection->io.context, reinterpret_cast<const std::uint8_t*>(input),
                            static_cast<std::size_t>(size));
    switch (result.status) {
    case IoStatus::Ok:
        if (result.bytes == 0 || result.bytes > static_cast<std::size_t>(size) ||
            result.bytes > static_cast<std::size_t>(INT_MAX)) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        return static_cast<int>(result.bytes);
    case IoStatus::WantRead:
    case IoStatus::WantWrite:
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    case IoStatus::Closed:
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    case IoStatus::Failed:
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return WOLFSSL_CBIO_ERR_GENERAL;
}

void key_log(const WOLFSSL* ssl, const char* line) {
    if (ssl == nullptr || line == nullptr) {
        return;
    }
    auto* connection =
        static_cast<WolfConnection*>(wolfSSL_GetIOReadCtx(const_cast<WOLFSSL*>(ssl)));
    if (connection == nullptr) {
        return;
    }
    const auto& sink = connection->context->services.key_log;
    if (sink.append != nullptr) {
        const std::size_t length = std::strlen(line);
        (void)sink.append(sink.context, line, length);
    }
}

std::string unsupported_reason(const TlsConfig& config, std::span<const std::uint8_t> saved) {
    if (config.cipher != kCipher) {
        return "wolfSSL adapter supports only TLS_AES_128_GCM_SHA256";
    }
    if (config.group != kGroup) {
        return std::string("this wolfSSL adapter supports only ") + kGroup;
    }
    if (config.signature != kSignature) {
        return "wolfSSL adapter supports only ecdsa_secp256r1_sha256";
    }
    if (!config.framework_io) {
        return "wolfSSL adapter requires framework callback I/O";
    }
    if (!config.compatibility_ccs) {
        return "wolfSSL dependency is built with TLS 1.3 compatibility CCS enabled";
    }
    if (config.tickets != 0) {
        return "wolfSSL adapter supports exactly zero session tickets";
    }
    if (config.record_size_limit != 0) {
        return "wolfSSL adapter does not support record_size_limit";
    }
    if (config.certificate_compression) {
        return "wolfSSL adapter does not support certificate compression";
    }
    if (!saved.empty()) {
        return "wolfSSL adapter does not support saved connection context";
    }
    if (config.ca_file.empty()) {
        return "wolfSSL adapter requires a CA file";
    }
    if (config.server_name.empty() || config.server_name.size() > USHRT_MAX) {
        return "wolfSSL adapter requires a server name no longer than 65535 bytes";
    }
    return {};
}

bool load_identity(WolfContext& context, const std::string& certificate, const std::string& key,
                   const char* description) {
    if (certificate.empty() || key.empty()) {
        context.setup_error =
            std::string(description) + " certificate and private key are required";
        return false;
    }
    if (wolfSSL_CTX_use_certificate_chain_file(context.ssl_context, certificate.c_str()) !=
        WOLFSSL_SUCCESS) {
        set_setup_error(context, "wolfSSL_CTX_use_certificate_chain_file");
        return false;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(context.ssl_context, key.c_str(), WOLFSSL_FILETYPE_PEM) !=
        WOLFSSL_SUCCESS) {
        set_setup_error(context, "wolfSSL_CTX_use_PrivateKey_file");
        return false;
    }
    if (wolfSSL_CTX_check_private_key(context.ssl_context) != WOLFSSL_SUCCESS) {
        set_setup_error(context, "wolfSSL_CTX_check_private_key");
        return false;
    }
    return true;
}

const char* adapter_name() noexcept {
#ifdef TURTLE_ADAPTER_ID
    return TURTLE_ADAPTER_ID;
#else
    return "wolfssl";
#endif
}

Declaration declaration(const Context* base) {
    Declaration value;
    value.library = "wolfSSL";
    value.source_version = kWolfSslVersion;
    value.source_url = "https://github.com/wolfSSL/wolfssl/tree/v5.8.2-stable";
#ifdef TURTLE_MLKEM
    value.source_version = "5.8.2;decea12e223869c8f8f3ab5a53dc90b69f436eb2";
    value.technique = "mlkem768-tls13";
    value.implementation = TURTLE_MLKEM_AVX2 ? "mlkem-avx2-dispatch" : "mlkem-portable-c";
#endif
#ifdef TURTLE_BITHAC
    value.source_version = "5.7.0;68ad825a37ef72cc1db4a67eb6d13275cc61f8aa";
    value.source_url =
        "https://github.com/RWTH-SPICe/BiTHaC/tree/68ad825a37ef72cc1db4a67eb6d13275cc61f8aa";
    value.technique = "bithac-tls13";
    value.implementation =
        TURTLE_BITHAC_ENABLED ? "author-caching-enabled" : "same-source-caching-disabled";
#endif
#ifdef TURTLE_WOLFSSL_TRACE_PATCH
    value.patch_hash = TURTLE_PATCH_SHA256;
    value.scenarios.push_back(Scenario::FinishedPing);
    value.send_policies.push_back(SendPolicy::ServerHelloFirst);
    value.internal_events = {TraceOperation::MessageProcess, TraceOperation::RecordEncrypt,
                             TraceOperation::RecordDecrypt, TraceOperation::LibraryMessageWrite};
    value.internal_events_note =
        "DoTls13 certificate/verify/Finished/extensions processing; Encrypt/DecryptTls13; "
        "SendTls13 spans include construction, record and I/O, not pure generation";
#if TURTLE_WOLFSSL_TRACE_PATCH >= 2
    value.internal_events.push_back(TraceOperation::MessageGenerate);
    value.internal_events_note +=
        "; additional Hello processing; stack-owned message_generate spans stop before "
        "BuildTls13Message/SendBuffered (Certificate fragments are separate spans); "
        "generation includes in-function buffer/message preparation and excludes encrypted "
        "record construction and I/O; prerequisite keys outside these spans remain separate";
#endif
    value.server_ping_note = "explicit yield after ServerFinished submission with application "
                             "traffic keys; before ClientFinished";
#endif
    value.version = kWolfSslVersion;
    value.build_options =
        "TLS1.3,ECC,AES128-GCM,OPENSSL_EXTRA,SECRET_CALLBACK,"
        "SESSION_TICKET,TLS13_MIDDLEBOX_COMPAT,WOLFSSL_GETRANDOM; "
        "key log is sink-only (no file); "
        "version/cipher/group/signature/resumption are queried from wolfSSL; "
        "hello_retry_request=false is inferred from the forced single key-share group";
#ifdef TURTLE_LIBRARY_LINKAGE
    value.build_options += ";tls_linkage=" TURTLE_LIBRARY_LINKAGE;
#endif
    value.context_description =
        "full handshake only; session tickets disabled; HRR has no wolfSSL observation hook";
#ifdef TURTLE_MLKEM
    value.build_options += ";ML_KEM_768; source-local USE_INTEL_SPEEDUP in wc_mlkem.c/poly.c; "
                           "other crypto objects identical across pair";
    value.build_options += TURTLE_MLKEM_AVX2 ? ";ML-KEM AVX2 dispatch enabled"
                                             : ";WC_MLKEM_NO_ASM in ML-KEM source files";
    value.internal_events.insert(
        value.internal_events.end(),
        {TraceOperation::KemKeygen, TraceOperation::KemEncapsulate, TraceOperation::KemDecapsulate,
         TraceOperation::KemPolynomialKeygen, TraceOperation::KemPolynomialEncapsulate,
         TraceOperation::KemPolynomialDecapsulate});
    value.internal_events_note +=
        "; kem_* brackets actual TLS wc_MlKemKey calls including RNG; kem_polynomial_* "
        "brackets actual arithmetic dispatch (message_type 1=C, 2=AVX2); "
        "decapsulation includes a separate polynomial re-encryption call";
#endif
#ifdef TURTLE_BITHAC
    value.build_options +=
        TURTLE_BITHAC_ENABLED ? ";WOLFSSL_CACHED_INFO,WOLFSSL_SSC" : ";caching-disabled";
    value.context_description +=
        "; original author code; cache is library process-global, initially empty in each fresh "
        "role process; first measured connection populates it; subsequent connections reuse it; no "
        "small-cert-cache prevalidation";
#if TURTLE_BITHAC_ENABLED
    value.internal_events.push_back(TraceOperation::CachedCertificateWrite);
    value.internal_events_note +=
        "; cached_certificate_write brackets CISSC_SendCachedTls13Certificate including record and "
        "I/O; this is the actual research path";
#endif
#endif
    value.callback_io = true;
    const auto* context = dynamic_cast<const WolfContext*>(base);
    value.allocator_hooks = context != nullptr && context->allocator_installed;
    value.key_log = true;
    value.plaintext_hook = false;
    value.extra_threads = false;
    value.context_serialization = false;
    value.is_mock = false;
    value.read_ahead = false;
    value.read_ahead_note =
        "wolfSSL stores a disabled compatibility flag, but its TLS stream reader does "
        "not consult that flag; the pinned reader independently requests the exact remaining "
        "header or body bytes";
    value.memory_note =
        value.allocator_hooks
            ? "wolfSSL allocations use host callbacks; excludes adapter C++ objects and caller "
              "buffers"
            : "TLS allocator hooks are not installed in timing mode; TLS heap is unobserved";
    return value;
}

Context* setup(Role role, const TlsConfig& config, const HostServices& services,
               std::span<const std::uint8_t> saved) {
    auto* context = new (std::nothrow) WolfContext(role, config, services);
    if (context == nullptr) {
        return nullptr;
    }
    context->setup_error = unsupported_reason(config, saved);
    if (!context->setup_error.empty()) {
        return context;
    }
    if (services.memory_mode) {
        const auto& allocator = context->services.allocator;
        if (active_allocator != nullptr || allocator.allocate == nullptr ||
            allocator.reallocate == nullptr || allocator.deallocate == nullptr) {
            context->setup_error =
                "wolfSSL memory mode requires one context and all allocator callbacks";
            return context;
        }
        (void)wolfSSL_GetAllocators(&context->previous_malloc, &context->previous_free,
                                    &context->previous_realloc);
        active_allocator = &allocator;
        if (wolfSSL_SetAllocators(host_allocate, host_deallocate, host_reallocate) != 0) {
            active_allocator = nullptr;
            context->setup_error = "wolfSSL_SetAllocators failed";
            return context;
        }
        context->allocator_installed = true;
    }
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        context->setup_error = "wolfSSL_Init failed";
        return context;
    }
    context->library_initialized = true;

    WOLFSSL_METHOD* method =
        role == Role::Client ? wolfTLSv1_3_client_method() : wolfTLSv1_3_server_method();
    if (method == nullptr) {
        set_setup_error(*context, "wolfTLSv1_3_method");
        return context;
    }
    context->ssl_context = wolfSSL_CTX_new(method);
    if (context->ssl_context == nullptr) {
        set_setup_error(*context, "wolfSSL_CTX_new");
        return context;
    }
    wolfSSL_CTX_SetIORecv(context->ssl_context, io_receive);
    wolfSSL_CTX_SetIOSend(context->ssl_context, io_send);
    wolfSSL_CTX_set_keylog_callback(context->ssl_context, key_log);
    if (wolfSSL_CTX_set_read_ahead(context->ssl_context, 0) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_get_read_ahead(context->ssl_context) != 0) {
        context->setup_error = "wolfSSL_CTX read-ahead compatibility flag could not be disabled";
        return context;
    }

    if (wolfSSL_CTX_set_cipher_list(context->ssl_context, kWolfCipher) != WOLFSSL_SUCCESS) {
        set_setup_error(*context, "wolfSSL_CTX_set_cipher_list");
        return context;
    }
    int group = kWolfGroup;
    if (wolfSSL_CTX_set_groups(context->ssl_context, &group, 1) != WOLFSSL_SUCCESS) {
        set_setup_error(*context, "wolfSSL_CTX_set_groups");
        return context;
    }
    if (wolfSSL_CTX_load_verify_locations(context->ssl_context, config.ca_file.c_str(), nullptr) !=
        WOLFSSL_SUCCESS) {
        set_setup_error(*context, "wolfSSL_CTX_load_verify_locations");
        return context;
    }

    if (role == Role::Server) {
        if (!load_identity(*context, config.server_certificate, config.server_key, "server")) {
            return context;
        }
        const int verify_mode = config.mutual_auth
                                    ? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
                                    : WOLFSSL_VERIFY_NONE;
        wolfSSL_CTX_set_verify(context->ssl_context, verify_mode, nullptr);
        if (wolfSSL_CTX_no_ticket_TLSv13(context->ssl_context) != 0 ||
            wolfSSL_CTX_set_num_tickets(context->ssl_context, 0) != WOLFSSL_SUCCESS) {
            context->setup_error = "failed to disable TLS 1.3 session tickets";
        }
    } else {
        wolfSSL_CTX_set_verify(context->ssl_context, WOLFSSL_VERIFY_PEER, nullptr);
        if (config.mutual_auth &&
            !load_identity(*context, config.client_certificate, config.client_key, "client")) {
            return context;
        }
    }
    return context;
}

Connection* open(Context* base, const Io& io) {
    auto* context = dynamic_cast<WolfContext*>(base);
    if (context == nullptr) {
        return nullptr;
    }
    auto* connection = new (std::nothrow) WolfConnection(context, io);
    if (connection == nullptr) {
        return nullptr;
    }
    if (!context->setup_error.empty()) {
        connection->last_error = context->setup_error;
        return connection;
    }
    if (io.send == nullptr || io.recv == nullptr) {
        connection->last_error = "framework callback I/O is incomplete";
        return connection;
    }
    connection->ssl = wolfSSL_new(context->ssl_context);
    if (connection->ssl == nullptr) {
        connection->last_error = "wolfSSL_new failed";
        return connection;
    }
    connection->trace.sink = context->services.trace;
    connection->trace.enabled = context->services.trace_mode;
#ifdef TURTLE_WOLFSSL_TRACE_PATCH
    if (context->role == Role::Server && (context->config.scenario == Scenario::ServerPing ||
                                          context->config.scenario == Scenario::FinishedPing))
        wolfSSL_turtle_enable_ping(connection->ssl);
    if (context->services.trace_mode) {
        wolfSSL_set_msg_callback_arg(connection->ssl, connection);
        wolfSSL_set_msg_callback(connection->ssl, [](int, int version, int type, const void* bytes,
                                                     std::size_t size, WOLFSSL*, void* arg) {
            static_cast<WolfConnection*>(arg)->trace.message(version, type, bytes, size);
        });
    }
#endif
    wolfSSL_SetIOReadCtx(connection->ssl, connection);
    wolfSSL_SetIOWriteCtx(connection->ssl, connection);
    if (context->role == Role::Client) {
#if defined(TURTLE_BITHAC) && TURTLE_BITHAC_ENABLED
        if (wolfSSL_CI_set_peer_id(connection->ssl, context->config.server_name.c_str()) != 0) {
            connection->last_error = "wolfSSL_CI_set_peer_id failed";
            return connection;
        }
#endif
        if (wolfSSL_check_domain_name(connection->ssl, context->config.server_name.c_str()) !=
            WOLFSSL_SUCCESS) {
            connection->last_error = "wolfSSL_check_domain_name failed";
            return connection;
        }
        if (wolfSSL_UseSNI(connection->ssl, WOLFSSL_SNI_HOST_NAME,
                           context->config.server_name.data(),
                           static_cast<unsigned short>(context->config.server_name.size())) !=
            WOLFSSL_SUCCESS) {
            connection->last_error = "wolfSSL_UseSNI failed";
        }
    }
    return connection;
}

Step translate_operation(WolfConnection& connection, int result, const char* operation) {
    if (connection.trace.failed)
        return Step::Failed;
    if (result == WOLFSSL_SUCCESS) {
        return Step::Complete;
    }
    const int error = wolfSSL_get_error(connection.ssl, result);
    if (error == WOLFSSL_ERROR_WANT_READ) {
        return Step::WantRead;
    }
    if (error == WOLFSSL_ERROR_WANT_WRITE) {
        return Step::WantWrite;
    }
    set_wolf_error(connection, operation, error);
    return Step::Failed;
}

Step handshake_step(Connection* base) {
    auto* connection = dynamic_cast<WolfConnection*>(base);
    if (connection == nullptr || connection->ssl == nullptr || !connection->last_error.empty()) {
        return Step::Failed;
    }
    if (connection->handshake_done) {
        return Step::Complete;
    }
    const int result = connection->context->role == Role::Client ? wolfSSL_connect(connection->ssl)
                                                                 : wolfSSL_accept(connection->ssl);
#ifdef TURTLE_WOLFSSL_TRACE_PATCH
    if (!connection->trace.failed && !connection->ping_reported &&
        connection->context->role == Role::Server &&
        (connection->context->config.scenario == Scenario::ServerPing ||
         connection->context->config.scenario == Scenario::FinishedPing) &&
        wolfSSL_turtle_write_ready(connection->ssl)) {
        connection->ping_reported = true;
        return Step::ApplicationWriteReady;
    }
#endif
    const Step step = translate_operation(*connection, result, "TLS handshake");
    if (step == Step::Complete) {
        connection->handshake_done = true;
    }
    return step;
}

bool peer_certificate_present(WOLFSSL* ssl) {
    WOLFSSL_X509* certificate = wolfSSL_get_peer_certificate(ssl);
    if (certificate == nullptr) {
        return false;
    }
    wolfSSL_X509_free(certificate);
    return true;
}

Verification peer_verification(Connection* base) {
    auto* connection = dynamic_cast<WolfConnection*>(base);
    if (connection == nullptr || connection->ssl == nullptr || !connection->handshake_done) {
        return Verification::Failed;
    }
    if (connection->context->role == Role::Server && !connection->context->config.mutual_auth) {
        return Verification::NotApplicable;
    }
    return wolfSSL_get_verify_result(connection->ssl) == 0 &&
                   peer_certificate_present(connection->ssl)
               ? Verification::Passed
               : Verification::Failed;
}

Negotiated negotiated(Connection* base) {
    Negotiated value;
    auto* connection = dynamic_cast<WolfConnection*>(base);
    if (connection == nullptr || connection->ssl == nullptr || !connection->handshake_done) {
        return value;
    }
    const char* version = wolfSSL_get_version(connection->ssl);
    if (version != nullptr && std::strcmp(version, "TLSv1.3") == 0) {
        value.version = "TLS1.3";
    }
    const char* cipher = wolfSSL_get_cipher_name(connection->ssl);
    if (cipher != nullptr && std::strcmp(cipher, kWolfCipher) == 0) {
        value.cipher = kCipher;
    }
    const char* curve = wolfSSL_get_curve_name(connection->ssl);
#ifdef TURTLE_MLKEM
    if (curve != nullptr && std::strcmp(curve, kGroup) == 0) {
        value.group = kGroup;
    }
#else
    if (curve != nullptr &&
        (std::strcmp(curve, "SECP256R1") == 0 || std::strcmp(curve, "secp256r1") == 0 ||
         std::strcmp(curve, "P-256") == 0)) {
        value.group = kGroup;
    }
#endif
    int hash_nid = 0;
    int signature_nid = 0;
    const bool signature_observed =
        connection->context->role == Role::Client
            ? wolfSSL_get_peer_signature_nid(connection->ssl, &hash_nid) == WOLFSSL_SUCCESS &&
                  wolfSSL_get_peer_signature_type_nid(connection->ssl, &signature_nid) ==
                      WOLFSSL_SUCCESS
            : wolfSSL_get_signature_nid(connection->ssl, &hash_nid) == WOLFSSL_SUCCESS &&
                  wolfSSL_get_signature_type_nid(connection->ssl, &signature_nid) ==
                      WOLFSSL_SUCCESS;
    if (signature_observed && hash_nid == NID_sha256 && signature_nid == NID_X9_62_id_ecPublicKey) {
        value.signature = kSignature;
    }
    value.resumed = wolfSSL_session_reused(connection->ssl) == 1;
    value.hello_retry_request = false;
    value.peer_certificate_present = peer_certificate_present(connection->ssl);
    return value;
}

AppResult app_send(Connection* base, const std::uint8_t* data, std::size_t size) {
    auto* connection = dynamic_cast<WolfConnection*>(base);
    if (connection == nullptr || connection->ssl == nullptr || data == nullptr || size == 0 ||
        size > static_cast<std::size_t>(INT_MAX)) {
        return {Step::Failed, 0};
    }
    const int result = wolfSSL_write(connection->ssl, data, static_cast<int>(size));
    if (result > 0) {
        return {Step::Complete, static_cast<std::size_t>(result)};
    }
    return {translate_operation(*connection, result, "wolfSSL_write"), 0};
}

AppResult app_recv(Connection* base, std::uint8_t* data, std::size_t size) {
    auto* connection = dynamic_cast<WolfConnection*>(base);
    if (connection == nullptr || connection->ssl == nullptr || data == nullptr || size == 0 ||
        size > static_cast<std::size_t>(INT_MAX)) {
        return {Step::Failed, 0};
    }
    const int result = wolfSSL_read(connection->ssl, data, static_cast<int>(size));
    if (result > 0) {
        return {Step::Complete, static_cast<std::size_t>(result)};
    }
    return {translate_operation(*connection, result, "wolfSSL_read"), 0};
}

const char* error(const Connection* base) noexcept {
    const auto* connection = dynamic_cast<const WolfConnection*>(base);
    return connection == nullptr ? "invalid wolfSSL connection" : connection->last_error.c_str();
}

void close(Connection* base) noexcept {
    auto* connection = dynamic_cast<WolfConnection*>(base);
    if (connection == nullptr) {
        return;
    }
    if (connection->ssl != nullptr) {
        wolfSSL_free(connection->ssl);
    }
    delete connection;
}

std::vector<std::uint8_t> save(Context*) {
    return {};
}

void teardown(Context* base) noexcept {
    auto* context = dynamic_cast<WolfContext*>(base);
    if (context == nullptr) {
        return;
    }
    if (context->ssl_context != nullptr) {
        wolfSSL_CTX_free(context->ssl_context);
    }
    if (context->library_initialized) {
        (void)wolfSSL_Cleanup();
    }
    if (context->allocator_installed) {
        (void)wolfSSL_SetAllocators(context->previous_malloc, context->previous_free,
                                    context->previous_realloc);
        active_allocator = nullptr;
    }
    delete context;
}

} // namespace

extern "C" turtle::ImplementationApi turtle_adapter_v3() {
    turtle::ImplementationApi api;
    api.version = turtle::adapter_api_version;
    api.name = adapter_name;
    api.declaration = declaration;
    api.setup = setup;
    api.open = open;
    api.handshake_step = handshake_step;
    api.peer_verification = peer_verification;
    api.negotiated = negotiated;
    api.app_send = app_send;
    api.app_recv = app_recv;
    api.error = error;
    api.close = close;
    api.save = save;
    api.teardown = teardown;
    return api;
}
