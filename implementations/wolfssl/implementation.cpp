#include <turtle/role.h>
#include "implementation.hpp"
#include "configure.hpp"
#include <wolfssl/wolfcrypt/asn.h>
#include <algorithm>
#include <climits>
#include <cerrno>
#include <cstring>
#include <memory>
namespace {
#ifndef WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY
// Some builds accept a matching CN on a leaf without a DNS SAN. Inspect the
// peer DER in the public verification callback; never override a chain error.
// The native TLS hostname check still does the actual DNS matching.
int require_dns_san(int verified, WOLFSSL_X509_STORE_CTX* store) {
    if (!verified || !store) return 0;
    if (store->error_depth != 0) return 1;
    if (!store->certs || store->totalCerts < 1) return 0;
    const auto& leaf = store->certs[0];
    DecodedCert certificate{};
    wc_InitDecodedCert(&certificate, leaf.buffer, leaf.length, nullptr);
    bool found = false;
    if (wc_ParseCert(&certificate, CERT_TYPE, NO_VERIFY, nullptr) == 0)
        for (const auto* name = certificate.altNames; name; name = name->next)
            if (name->type == ASN_DNS_TYPE) { found = true; break; }
    wc_FreeDecodedCert(&certificate);
    return found;
}
#endif

struct State {
    bool initialized = false;
    WOLFSSL_CTX* context = nullptr;
    WOLFSSL* ssl = nullptr;
    turtle_transport transport{};
    turtle_role role = TURTLE_CLIENT;
    bool starting_first = false, sent_flight = false;
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

std::unique_ptr<State> make_tls(turtle_role role, int argc, const char* const* argv, turtle_transport transport) {
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
    if (config.trusted_certificate) {
#if defined(WOLFSSL_ALLOW_NO_CN_IN_SAN)
        return nullptr; // This alternate native policy permits CN over a mismatching SAN.
#elif !defined(WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY)
        wolfSSL_CertManagerSetVerify(wolfSSL_CTX_GetCertManager(s->context), require_dns_san);
#endif
    }
    wolfSSL_CTX_SetIORecv(s->context, receive);
    wolfSSL_CTX_SetIOSend(s->context, send);
    s->ssl = wolfSSL_new(s->context);
    if (!s->ssl || (role == TURTLE_SERVER && wolfSSL_no_ticket_TLSv13(s->ssl) != 0)) return nullptr;
    const int verify = role == TURTLE_CLIENT ? WOLFSSL_VERIFY_PEER :
        transport.mutual_auth ? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : WOLFSSL_VERIFY_NONE;
    wolfSSL_set_verify(s->ssl, verify, nullptr);
    if (verify != WOLFSSL_VERIFY_NONE &&
        wolfSSL_check_domain_name(s->ssl, config.peer_name) != WOLFSSL_SUCCESS) return nullptr;
    wolfSSL_SetIOReadCtx(s->ssl, s.get());
    wolfSSL_SetIOWriteCtx(s->ssl, s.get());
    if (role == TURTLE_CLIENT &&
        (wolfSSL_UseSNI(s->ssl, WOLFSSL_SNI_HOST_NAME, config.peer_name,
                       static_cast<unsigned short>(std::strlen(config.peer_name))) != WOLFSSL_SUCCESS ||
         wolfSSL_UseKeyShare(s->ssl, static_cast<word16>(config.group)) != WOLFSSL_SUCCESS)) return nullptr;
    return s;
}

bool facts(const State& s, turtle_handshake_info& info) {
    if (!wolfSSL_is_init_finished(s.ssl)) return false;
    // This build need not retain the peer certificate: fresh certificate TLS,
    // a verified chain and a positive native domain-name check are enforced.
    const int reused = wolfSSL_session_reused(s.ssl);
    info = {static_cast<uint16_t>(wolfSSL_GetVersion(s.ssl) == WOLFSSL_TLSV1_3 ? TURTLE_TLS13 : 0),
            reused, wolfSSL_get_cipher_name(s.ssl), wolfSSL_get_curve_name(s.ssl),
            s.transport.mutual_auth ? TURTLE_PROFILE_MTLS_1RTT : TURTLE_PROFILE_SERVER_AUTH_1RTT,
            reused ? -1 : static_cast<int>(s.role == TURTLE_CLIENT || s.transport.mutual_auth),
            LIBWOLFSSL_VERSION_HEX == 0x05009004 ? TURTLE_UNPADDED_APPLICATION_TAIL : 0};
    return true;
}

int step(turtle_session* session, State& s, const turtle_action& a) {
    auto call = [&](auto&& operation) {
        turtle_before(session);
        const int rc = operation();
        turtle_returned(session);
        return rc;
    };
    const int size = static_cast<int>(std::min(a.size, static_cast<size_t>(INT_MAX)));
    int rc;
    switch (a.op) {
    case TURTLE_FIRST_HS:
        s.starting_first = true;
        rc = call([&] { return wolfSSL_accept(s.ssl); });
        break;
    case TURTLE_HS:
        s.starting_first = false;
        rc = s.role == TURTLE_SERVER ? call([&] { return wolfSSL_accept(s.ssl); })
                                     : call([&] { return wolfSSL_connect(s.ssl); });
        break;
    case TURTLE_READ: rc = call([&] { return wolfSSL_read(s.ssl, a.in, size); }); break;
    case TURTLE_FIRST_WRITE:
    case TURTLE_WRITE: rc = call([&] { return wolfSSL_write(s.ssl, a.out, size); }); break;
    case TURTLE_SHUTDOWN:
        rc = call([&] { return wolfSSL_shutdown(s.ssl); });
        if (rc == WOLFSSL_SHUTDOWN_NOT_DONE) return turtle_submit(session, {TURTLE_AGAIN_READ, 0, 0}, nullptr);
        break;
    default: return -1;
    }
    turtle_result result{TURTLE_OK, 0, 0};
    turtle_handshake_info negotiated{};
    const turtle_handshake_info* evidence = nullptr;
    if (rc <= 0) {
        switch (wolfSSL_get_error(s.ssl, rc)) {
        case WOLFSSL_ERROR_WANT_READ:
            if (a.op == TURTLE_FIRST_HS && s.sent_flight) {
                // The public I/O boundary returned WANT_READ without consuming
                // the next client flight. Keep it closed through FIRST_WRITE.
                break;
            }
            result = {a.op == TURTLE_FIRST_WRITE ? TURTLE_ERROR : TURTLE_AGAIN_READ, 0, a.op == TURTLE_READ};
            break;
        case WOLFSSL_ERROR_WANT_WRITE: result = {TURTLE_AGAIN_WRITE, 0, 0}; break;
        case WOLFSSL_ERROR_ZERO_RETURN: result = {TURTLE_EOF, 0, 0}; break;
        default: result = {TURTLE_ERROR, 0, 0};
        }
    } else if (a.op == TURTLE_HS && facts(s, negotiated)) {
        evidence = &negotiated;
    } else if (a.op == TURTLE_FIRST_HS) {
        result.status = TURTLE_ERROR; // a completed ordinary handshake is not presend
    } else if (a.op == TURTLE_READ || a.op == TURTLE_WRITE || a.op == TURTLE_FIRST_WRITE) {
        result.bytes = static_cast<size_t>(rc);
    }
    return turtle_submit(session, result, evidence);
}
}

int turtle_wolfssl::run(int argc, char** argv) {
    constexpr unsigned hooks = (1u << TURTLE_IO_BEGIN) | (1u << TURTLE_IO_END);
    auto* session = turtle_session_open(argc, argv, "wolfSSL " LIBWOLFSSL_VERSION_STRING, hooks, 1);
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
