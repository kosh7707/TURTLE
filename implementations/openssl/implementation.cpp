#include <turtle/role.h>
#include <openssl/x509v3.h>
#include "implementation.hpp"
#include "configure.hpp"

#include <openssl/err.h>
#include <cerrno>
#include <memory>

namespace {

struct State {
    // 파괴 순서: SSL(BIO 포함), SSL_CTX, BIO_METHOD.
    std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> method{nullptr, BIO_meth_free};
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context{nullptr, SSL_CTX_free};
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
    turtle_transport transport{};
    bool eof = false;
    char early_scratch = 0;
};

// BIO_set_callback_ex reports the BIO API boundary; it is not the socket
// syscall. Return ret unchanged, including EOF and failure.
long bio_hook(BIO* bio, int op, const char*, std::size_t size, int, long,
              int ret, std::size_t* processed) {
    const int action = op & ~BIO_CB_RETURN;
    if (action != BIO_CB_READ && action != BIO_CB_WRITE) return ret;
    const auto& t = static_cast<State*>(BIO_get_data(bio))->transport;
    const bool post = (op & BIO_CB_RETURN) != 0;
    std::ptrdiff_t n = 0;
    if (post) n = ret > 0 && processed ? static_cast<std::ptrdiff_t>(*processed) : ret;
    const int saved = errno;
    t.observe(t.state, post ? TURTLE_BIO_END : TURTLE_BIO_BEGIN,
              action == BIO_CB_WRITE, nullptr, size, n);
    errno = saved;
    return ret;
}

void message_hook(int send, int, int type, const void* data, std::size_t size,
                  SSL*, void* arg) {
    if (type != SSL3_RT_HEADER && type != SSL3_RT_HANDSHAKE) return;
    const auto& t = static_cast<State*>(arg)->transport;
    const int saved = errno;
    t.observe(t.state, type == SSL3_RT_HEADER ? TURTLE_RECORD_HEADER : TURTLE_HANDSHAKE_MESSAGE,
              send, data, size, 0);
    errno = saved;
}

void set_retry(BIO* bio, std::ptrdiff_t result) {
    if (result == TURTLE_WANT_READ) BIO_set_retry_read(bio);
    else if (result == TURTLE_WANT_WRITE) BIO_set_retry_write(bio);
}
int receive(BIO* bio, char* buffer, std::size_t size, std::size_t* received) {
    auto& state = *static_cast<State*>(BIO_get_data(bio));
    BIO_clear_retry_flags(bio);
    const auto result = state.transport.receive(state.transport.state, buffer, size);
    set_retry(bio, result);
    state.eof = result == 0;
    *received = result > 0 ? static_cast<std::size_t>(result) : 0;
    return result > 0 ? 1 : (result == 0 ? 0 : -1);
}

int send(BIO* bio, const char* buffer, std::size_t size, std::size_t* sent) {
    auto& state = *static_cast<State*>(BIO_get_data(bio));
    BIO_clear_retry_flags(bio);
    const auto result = state.transport.send(state.transport.state, buffer, size);
    set_retry(bio, result);
    *sent = result > 0 ? static_cast<std::size_t>(result) : 0;
    return result > 0 ? 1 : (result == 0 ? 0 : -1);
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

std::unique_ptr<State> make_tls(turtle_role role, int argc, const char* const* argv, turtle_transport transport) {
    turtle_openssl::Configuration config;
    if (!turtle_openssl::parse(config, role, argc, argv)) return nullptr;
    if ((role == TURTLE_SERVER ? config.trusted_certificate != nullptr : config.certificate != nullptr)
        != (transport.mutual_auth != 0)) return nullptr;
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
    if (!state->ssl || SSL_set_record_padding_callback(state->ssl.get(), nullptr) != 1 ||
        SSL_set_block_padding(state->ssl.get(), 0) != 1 ||
        SSL_set_num_tickets(state->ssl.get(), 0) != 1) return nullptr;
    const int verify = role == TURTLE_CLIENT ? SSL_VERIFY_PEER :
        transport.mutual_auth ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_NONE;
    SSL_set_verify(state->ssl.get(), verify, nullptr);
    SSL_set_mode(state->ssl.get(), SSL_MODE_ENABLE_PARTIAL_WRITE);
    if (verify != SSL_VERIFY_NONE) {
        SSL_set_hostflags(state->ssl.get(), X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        if (SSL_set1_host(state->ssl.get(), config.peer_name) != 1) return nullptr;
    }
    BIO* bio = BIO_new(state->method.get());
    if (bio == nullptr)
        return nullptr;
    BIO_set_data(bio, state.get());
    BIO_set_init(bio, 1);
    if (transport.observe) {
        BIO_set_callback_ex(bio, bio_hook);
        SSL_set_msg_callback(state->ssl.get(), message_hook);
        SSL_set_msg_callback_arg(state->ssl.get(), state.get());
    }
    // 새 SSL에 같은 BIO를 연결하므로 참조 하나의 소유권을 넘긴다.
    SSL_set_bio(state->ssl.get(), bio, bio);
    if (config.role == TURTLE_SERVER) {
        SSL_set_accept_state(state->ssl.get());
    } else {
        SSL_set_connect_state(state->ssl.get());
        if (SSL_set_tlsext_host_name(state->ssl.get(), config.peer_name) != 1)
            return nullptr;
    }
    return state;
}

bool facts(SSL* ssl, bool mutual, turtle_handshake_info& info) {
    if (!SSL_is_init_finished(ssl) ||
        SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_NOT_SENT) return false;
    info = {static_cast<uint16_t>(SSL_version(ssl)), SSL_session_reused(ssl),
            SSL_get_cipher_name(ssl), SSL_get0_group_name(ssl),
            mutual ? TURTLE_PROFILE_MTLS_1RTT : TURTLE_PROFILE_SERVER_AUTH_1RTT,
            (SSL_get_verify_mode(ssl) & SSL_VERIFY_PEER) && SSL_get0_peer_certificate(ssl) &&
                SSL_get_verify_result(ssl) == X509_V_OK, TURTLE_UNPADDED_APPLICATION_TAIL};
    return true;
}

int step(turtle_session* session, State& s, const turtle_action& a) {
    auto* ssl = s.ssl.get();
    size_t bytes = 0;
    auto call = [&](auto&& operation) {
        ERR_clear_error();
        turtle_before(session);
        const int rc = operation();
        turtle_returned(session);
        return rc;
    };
    int rc;
    switch (a.op) {
    case TURTLE_HS: rc = call([&] { return SSL_do_handshake(ssl); }); break;
    case TURTLE_FIRST_HS:
        rc = call([&] { return SSL_read_early_data(ssl, &s.early_scratch, 1, &bytes); });
        // A SUCCESS here represents client 0-RTT data, forbidden in this profile.
        if (rc == SSL_READ_EARLY_DATA_SUCCESS || bytes ||
            (rc == SSL_READ_EARLY_DATA_FINISH && SSL_is_init_finished(ssl)))
            return turtle_submit(session, {TURTLE_ERROR, 0, 0}, nullptr);
        rc = rc == SSL_READ_EARLY_DATA_FINISH ? 1 : 0;
        break;
    case TURTLE_FIRST_WRITE: rc = call([&] { return SSL_write_early_data(ssl, a.out, a.size, &bytes); }); break;
    case TURTLE_WRITE: rc = call([&] { return SSL_write_ex(ssl, a.out, a.size, &bytes); }); break;
    case TURTLE_READ: rc = call([&] { return SSL_read_ex(ssl, a.in, a.size, &bytes); }); break;
    case TURTLE_SHUTDOWN:
        rc = call([&] { return SSL_shutdown(ssl); });
        if (rc == 0) return turtle_submit(session, {TURTLE_AGAIN_READ, 0, 0}, nullptr);
        break;
    default: return -1;
    }
    turtle_result result{TURTLE_OK, bytes, 0};
    turtle_handshake_info negotiated{};
    const turtle_handshake_info* evidence = nullptr;
    if (rc != 1) {
        switch (SSL_get_error(ssl, rc)) {
        case SSL_ERROR_WANT_READ:
            result = {TURTLE_AGAIN_READ, 0, a.op == TURTLE_WRITE || a.op == TURTLE_READ}; break;
        case SSL_ERROR_WANT_WRITE: result = {TURTLE_AGAIN_WRITE, 0, 0}; break;
        case SSL_ERROR_ZERO_RETURN: result = {TURTLE_EOF, 0, 0}; break;
        default: result = {TURTLE_ERROR, 0, 0};
        }
    } else if (a.op == TURTLE_HS && facts(ssl, s.transport.mutual_auth, negotiated)) {
        evidence = &negotiated;
    }
    return turtle_submit(session, result, evidence);
}
}

int turtle_openssl::run(int argc, char** argv) {
    constexpr unsigned hooks = (1u << TURTLE_BIO_BEGIN) | (1u << TURTLE_BIO_END) |
        (1u << TURTLE_RECORD_HEADER) | (1u << TURTLE_HANDSHAKE_MESSAGE);
    auto* session = turtle_session_open(argc, argv, OpenSSL_version(OPENSSL_VERSION), hooks, 1);
    if (!session) return 1;
    const auto* config = turtle_session_config(session);
    turtle_transport io{};
    {
        auto tls = turtle_session_transport(session, &io) == 1
            ? make_tls(config->role, config->argc, config->argv, io) : nullptr;
        if (turtle_session_ready(session, tls != nullptr) == 1) {
            turtle_action action{};
            while (turtle_pull(session, &action) == 1 && action.op != TURTLE_DONE)
                if (step(session, *tls, action) != 1) break;
        }
    }
    return turtle_session_close(session);
}
