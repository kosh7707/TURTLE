#include "implementation.hpp"
#include "configure.hpp"
#include <algorithm>
#include <climits>
#include <cstring>
#include <memory>
namespace {
struct State {
    bool initialized = false;
    WOLFSSL_CTX* context = nullptr;
    WOLFSSL* ssl = nullptr;
    turtle_transport transport{};
    turtle_role role = TURTLE_CLIENT;
    ~State() {
        if (ssl) wolfSSL_free(ssl);
        if (context) wolfSSL_CTX_free(context);
        if (initialized) wolfSSL_Cleanup();
    }
};
int receive(WOLFSSL*, char* buffer, int size, void* opaque) {
    auto& s = *static_cast<State*>(opaque);
    const auto n = s.transport.receive(s.transport.state, buffer, static_cast<size_t>(size));
    if (n > 0) return static_cast<int>(n);
    return n == 0 ? WOLFSSL_CBIO_ERR_CONN_CLOSE : WOLFSSL_CBIO_ERR_GENERAL;
}
int send(WOLFSSL*, char* buffer, int size, void* opaque) {
    auto& s = *static_cast<State*>(opaque);
    const auto n = s.transport.send(s.transport.state, buffer, static_cast<size_t>(size));
    return n > 0 ? static_cast<int>(n) : WOLFSSL_CBIO_ERR_GENERAL;
}
void* prepare(turtle_role role, int argc, const char* const* argv, turtle_transport transport) {
    turtle_wolfssl::Configuration config;
    if (!turtle_wolfssl::parse(config, role, argc, argv)) return nullptr;
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
    if (!s->ssl) return nullptr;
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
int handshake(void* opaque, turtle_handshake_info* info) {
    auto& s = *static_cast<State*>(opaque);
    const int result = s.role == TURTLE_SERVER ? wolfSSL_accept(s.ssl) : wolfSSL_connect(s.ssl);
    if (result != WOLFSSL_SUCCESS) return 0;
    *info = {static_cast<uint16_t>(wolfSSL_GetVersion(s.ssl) == WOLFSSL_TLSV1_3 ? TURTLE_TLS13 : 0),
             wolfSSL_session_reused(s.ssl), wolfSSL_get_cipher_name(s.ssl), wolfSSL_get_curve_name(s.ssl),
             TURTLE_PROFILE_SERVER_AUTH_1RTT};
    return 1;
}
ptrdiff_t read(void* opaque, void* buffer, size_t size) {
    auto* ssl = static_cast<State*>(opaque)->ssl;
    const int result = wolfSSL_read(ssl, buffer, static_cast<int>(std::min(size, static_cast<size_t>(INT_MAX))));
    if (result > 0) return result;
    return wolfSSL_get_error(ssl, result) == WOLFSSL_ERROR_ZERO_RETURN ? 0 : -1;
}
ptrdiff_t write(void* opaque, const void* buffer, size_t size) {
    const int result = wolfSSL_write(static_cast<State*>(opaque)->ssl, buffer,
                                   static_cast<int>(std::min(size, static_cast<size_t>(INT_MAX))));
    return result > 0 ? result : -1;
}
int shutdown(void* opaque) {
    auto* ssl = static_cast<State*>(opaque)->ssl;
    const int result = wolfSSL_shutdown(ssl);
    return (result == WOLFSSL_SHUTDOWN_NOT_DONE ? wolfSSL_shutdown(ssl) : result) == WOLFSSL_SUCCESS;
}
}
turtle_implementation turtle_wolfssl::implementation() {
    return {"wolfSSL " LIBWOLFSSL_VERSION_STRING, prepare, release, handshake, read, write, shutdown};
}
