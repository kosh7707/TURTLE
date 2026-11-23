#include "implementation.hpp"
#include "configure.hpp"
#include <algorithm>
#include <climits>
#include <cerrno>
#include <cstring>
#include <memory>
namespace {
struct State {
    bool initialized = false;
    WOLFSSL_CTX* context = nullptr;
    WOLFSSL* ssl = nullptr;
    turtle_transport transport{};
    turtle_role role = TURTLE_CLIENT;
    bool starting_first = false, sent_flight = false, first_ready = false;
    ~State() {
        if (ssl) wolfSSL_free(ssl);
        if (context) wolfSSL_CTX_free(context);
        if (initialized) wolfSSL_Cleanup();
    }
};
void observe(const State& s, turtle_hook hook, bool sending, int size, ptrdiff_t processed) {
    if (!s.transport.observe) return;
    const int saved = errno;
    s.transport.observe(s.transport.state, hook, sending, nullptr, static_cast<size_t>(size), processed);
    errno = saved;
}

int io_status(ptrdiff_t n) {
    if (n > 0) return static_cast<int>(n);
    if (n == TURTLE_WANT_READ) return WOLFSSL_CBIO_ERR_WANT_READ;
    if (n == TURTLE_WANT_WRITE) return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return n == 0 ? WOLFSSL_CBIO_ERR_CONN_CLOSE : WOLFSSL_CBIO_ERR_GENERAL;
}

int receive(WOLFSSL*, char* buffer, int size, void* opaque) {
    auto& s = *static_cast<State*>(opaque);
    observe(s, TURTLE_IO_BEGIN, false, size, 0);
    // At the first read following a server flight, return control before
    // consuming client credentials/Finished, even if TCP already has them.
    const auto n = s.starting_first && s.sent_flight ? static_cast<ptrdiff_t>(TURTLE_WANT_READ)
        : s.transport.receive(s.transport.state, buffer, static_cast<size_t>(size));
    observe(s, TURTLE_IO_END, false, size, n);
    return io_status(n);
}

int send(WOLFSSL*, char* buffer, int size, void* opaque) {
    auto& s = *static_cast<State*>(opaque);
    observe(s, TURTLE_IO_BEGIN, true, size, 0);
    const auto n = s.transport.send(s.transport.state, buffer, static_cast<size_t>(size));
    if (n > 0 && s.starting_first) s.sent_flight = true;
    observe(s, TURTLE_IO_END, true, size, n);
    return io_status(n);
}

void* prepare(turtle_role role, int argc, const char* const* argv, turtle_transport transport) {
    turtle_wolfssl::Configuration config;
    if (!turtle_wolfssl::parse(config, role, argc, argv)) return nullptr;
    if ((role == TURTLE_SERVER ? config.trusted_certificate != nullptr : config.certificate != nullptr)
        != (transport.mutual_auth != 0)) return nullptr;
    auto s = std::make_unique<State>();
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) return nullptr;
    s->initialized = true;
    s->transport = transport;
    s->role = role;
    s->context = wolfSSL_CTX_new(role == TURTLE_SERVER ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method());
    if (!s->context || !turtle_wolfssl::configure(s->context, config)) return nullptr;
    wolfSSL_CTX_SetIORecv(s->context, receive);
    wolfSSL_CTX_SetIOSend(s->context, send);
    s->ssl = wolfSSL_new(s->context);
    if (!s->ssl || (role == TURTLE_SERVER && wolfSSL_no_ticket_TLSv13(s->ssl) != 0)) return nullptr;
    const int verify = role == TURTLE_CLIENT ? WOLFSSL_VERIFY_PEER :
        transport.mutual_auth ? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : WOLFSSL_VERIFY_NONE;
    wolfSSL_set_verify(s->ssl, verify, nullptr);
    wolfSSL_SetIOReadCtx(s->ssl, s.get());
    wolfSSL_SetIOWriteCtx(s->ssl, s.get());
    if (role == TURTLE_CLIENT &&
        (wolfSSL_check_domain_name(s->ssl, config.peer_name) != WOLFSSL_SUCCESS ||
         wolfSSL_UseSNI(s->ssl, WOLFSSL_SNI_HOST_NAME, config.peer_name,
                       static_cast<unsigned short>(std::strlen(config.peer_name))) != WOLFSSL_SUCCESS ||
         wolfSSL_UseKeyShare(s->ssl, static_cast<word16>(config.group)) != WOLFSSL_SUCCESS)) return nullptr;
    return s.release();
}
void release(void* opaque) { delete static_cast<State*>(opaque); }
int status(WOLFSSL* ssl, int rc) {
    switch (wolfSSL_get_error(ssl, rc)) {
        case WOLFSSL_ERROR_WANT_READ: return TURTLE_WANT_READ;
        case WOLFSSL_ERROR_WANT_WRITE: return TURTLE_WANT_WRITE;
        case WOLFSSL_ERROR_ZERO_RETURN: return 0;
        default: return -1;
    }
}

int handshake(void* opaque) {
    auto& s = *static_cast<State*>(opaque);
    const int rc = s.role == TURTLE_SERVER ? wolfSSL_accept(s.ssl) : wolfSSL_connect(s.ssl);
    return rc == WOLFSSL_SUCCESS ? 1 : status(s.ssl, rc);
}

int query(void* opaque, turtle_handshake_info* info) {
    auto& s = *static_cast<State*>(opaque);
    if (!wolfSSL_is_init_finished(s.ssl)) return 0;
    // The pinned build does not retain peer certificates. A new, non-PSK
    // credential handshake under the enforced verify mode (and required peer
    // certificate on a mutual server) is the authentication evidence.
    const int reused = wolfSSL_session_reused(s.ssl);
    *info = {static_cast<uint16_t>(wolfSSL_GetVersion(s.ssl) == WOLFSSL_TLSV1_3 ? TURTLE_TLS13 : 0),
             reused, wolfSSL_get_cipher_name(s.ssl), wolfSSL_get_curve_name(s.ssl),
             s.transport.mutual_auth ? TURTLE_PROFILE_MTLS_1RTT : TURTLE_PROFILE_SERVER_AUTH_1RTT,
             reused ? -1 : static_cast<int>(s.role == TURTLE_CLIENT || s.transport.mutual_auth),
             // 5.9.4 BuildTls13Message adds padding for DTLS only. Do not
             // extrapolate that source-level guarantee to unexamined builds.
             LIBWOLFSSL_VERSION_HEX == 0x05009004 ? TURTLE_UNPADDED_APPLICATION_TAIL : 0};
    return 1;
}

ptrdiff_t read(void* opaque, void* buffer, size_t size) {
    auto* ssl = static_cast<State*>(opaque)->ssl;
    const int result = wolfSSL_read(ssl, buffer, static_cast<int>(std::min(size, static_cast<size_t>(INT_MAX))));
    if (result > 0) return result;
    return status(ssl, result);
}
ptrdiff_t write(void* opaque, const void* buffer, size_t size) {
    if (!size) return -1;
    auto* ssl = static_cast<State*>(opaque)->ssl;
    const int result = wolfSSL_write(ssl, buffer,
                                   static_cast<int>(std::min(size, static_cast<size_t>(INT_MAX))));
    return result > 0 ? result : status(ssl, result);
}
ptrdiff_t server_first(void* opaque, const void* buffer, size_t size) {
    auto& s = *static_cast<State*>(opaque);
    if (s.role != TURTLE_SERVER || wolfSSL_is_init_finished(s.ssl)) return -1;
    if (!s.first_ready) {
        s.starting_first = true;
        const int rc = handshake(opaque);
        if (!s.sent_flight || rc != TURTLE_WANT_READ) return rc == 1 ? -1 : rc;
        s.first_ready = true;
        // Keep the receive gate closed through write: if this flight wasn't
        // Finished (e.g. HRR), write must not finish a normal handshake.
    }
    const auto n = write(opaque, buffer, size);
    if (n == TURTLE_WANT_READ) return -1; // no early-write capability on this flight
    if (n > 0) s.starting_first = false;
    return n;
}
int shutdown(void* opaque) {
    auto* ssl = static_cast<State*>(opaque)->ssl;
    const int result = wolfSSL_shutdown(ssl);
    return result == WOLFSSL_SHUTDOWN_NOT_DONE ? TURTLE_WANT_READ :
           result == WOLFSSL_SUCCESS ? 1 : status(ssl, result);
}
}
turtle_implementation turtle_wolfssl::implementation() {
    return {"wolfSSL " LIBWOLFSSL_VERSION_STRING, prepare, release, handshake, read, write, shutdown, query, server_first,
            (1u << TURTLE_IO_BEGIN) | (1u << TURTLE_IO_END)};
}
