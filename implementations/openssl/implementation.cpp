#include <turtle/implementation.h>
#include "implementation.hpp"
#include "configure.hpp"

#include <openssl/err.h>
#include <memory>

namespace {

struct State {
    // 파괴 순서: SSL(BIO 포함), SSL_CTX, BIO_METHOD.
    std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> method{nullptr, BIO_meth_free};
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context{nullptr, SSL_CTX_free};
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
    turtle_transport transport{};
    bool eof = false;
};

int receive(BIO* bio, char* buffer, std::size_t size, std::size_t* received) {
    auto& state = *static_cast<State*>(BIO_get_data(bio));
    BIO_clear_retry_flags(bio);
    const auto result = state.transport.receive(state.transport.state, buffer, size);
    state.eof = result == 0;
    *received = result > 0 ? static_cast<std::size_t>(result) : 0;
    return result > 0 ? 1 : 0;
}

int send(BIO* bio, const char* buffer, std::size_t size, std::size_t* sent) {
    auto& state = *static_cast<State*>(BIO_get_data(bio));
    BIO_clear_retry_flags(bio);
    const auto result = state.transport.send(state.transport.state, buffer, size);
    *sent = result > 0 ? static_cast<std::size_t>(result) : 0;
    return result > 0 ? 1 : 0;
}

long control(BIO* bio, int command, long, void*) {
    if (command == BIO_CTRL_FLUSH)
        return 1; // TURTLE 전송 계층에는 미제출 출력 버퍼가 없다.
    if (command == BIO_CTRL_EOF) {
        const auto* state = static_cast<const State*>(BIO_get_data(bio));
        return state != nullptr && state->eof;
    }
    return 0;
}

void* prepare(turtle_role role, int argc, const char* const* argv, turtle_transport transport) {
    turtle_openssl::Configuration config;
    if (!turtle_openssl::parse(config, role, argc, argv)) return nullptr;
    auto state = std::make_unique<State>();
    state->transport = transport;
    state->method.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "TURTLE transport"));
    state->context.reset(SSL_CTX_new(TLS_method()));
    if (!state->method || !state->context ||
        BIO_meth_set_read_ex(state->method.get(), receive) != 1 ||
        BIO_meth_set_write_ex(state->method.get(), send) != 1 ||
        BIO_meth_set_ctrl(state->method.get(), control) != 1 ||
        !turtle_openssl::configure(state->context.get(), config))
        return nullptr;

    state->ssl.reset(SSL_new(state->context.get()));
    if (!state->ssl)
        return nullptr;
    BIO* bio = BIO_new(state->method.get());
    if (bio == nullptr)
        return nullptr;
    BIO_set_data(bio, state.get());
    BIO_set_init(bio, 1);
    // 새 SSL에 같은 BIO를 연결하므로 참조 하나의 소유권을 넘긴다.
    SSL_set_bio(state->ssl.get(), bio, bio);
    if (config.role == TURTLE_SERVER) {
        SSL_set_accept_state(state->ssl.get());
    } else {
        SSL_set_connect_state(state->ssl.get());
        if (SSL_set_tlsext_host_name(state->ssl.get(), config.peer_name) != 1 ||
            SSL_set1_host(state->ssl.get(), config.peer_name) != 1)
            return nullptr;
    }
    return state.release();
}

void release(void* opaque) noexcept { delete static_cast<State*>(opaque); }

int handshake(void* opaque, turtle_handshake_info* info) {
    ERR_clear_error();
    auto* ssl = static_cast<State*>(opaque)->ssl.get();
    if (SSL_do_handshake(ssl) != 1) return 0;
    *info = {static_cast<uint16_t>(SSL_version(ssl)), SSL_session_reused(ssl),
             SSL_get_cipher_name(ssl), SSL_get0_group_name(ssl), TURTLE_PROFILE_SERVER_AUTH_1RTT};
    return 1;
}

std::ptrdiff_t read(void* opaque, void* buffer, std::size_t size) {
    std::size_t received = 0;
    ERR_clear_error();
    auto* ssl = static_cast<State*>(opaque)->ssl.get();
    const int result = SSL_read_ex(ssl, buffer, size, &received);
    if (result == 1) return static_cast<std::ptrdiff_t>(received);
    return SSL_get_error(ssl, result) == SSL_ERROR_ZERO_RETURN ? 0 : -1;
}

std::ptrdiff_t write(void* opaque, const void* buffer, std::size_t size) {
    std::size_t sent = 0;
    ERR_clear_error();
    return SSL_write_ex(static_cast<State*>(opaque)->ssl.get(), buffer, size, &sent) == 1
        ? static_cast<std::ptrdiff_t>(sent) : -1;
}

int shutdown(void* opaque) {
    auto* ssl = static_cast<State*>(opaque)->ssl.get();
    ERR_clear_error();
    const int result = SSL_shutdown(ssl);
    return (result == 0 ? SSL_shutdown(ssl) : result) == 1;
}

} // namespace

turtle_implementation turtle_openssl::implementation() {
    return {OpenSSL_version(OPENSSL_VERSION), prepare, release, handshake,
            read, write, shutdown};
}
