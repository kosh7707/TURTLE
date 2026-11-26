#include <turtle/implementation.hpp>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <new>
#include <sys/socket.h>

struct turtle_tls {
    WOLFSSL_CTX *context = nullptr;
    WOLFSSL *session = nullptr;
    turtle_transport_hooks hooks{};
    int fd;
    bool verifies_peer = false, reported = false;
    void *report_context = nullptr;
    decltype(turtle_tls_config::report_session) report_session = nullptr;
};

static int receive(WOLFSSL *, char *bytes, int len, void *context) {
    auto *tls = static_cast<turtle_tls *>(context);
    const auto &h = tls->hooks;
    ssize_t n;
    do {
        h.transfer_begin(h.context, 0, static_cast<size_t>(len));
        n = recv(tls->fd, bytes, static_cast<size_t>(len), 0);
        h.transfer_end(h.context, 0, static_cast<size_t>(len), n,
                       reinterpret_cast<const unsigned char *>(bytes));
    } while (n < 0 && errno == EINTR);
    if (n == 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    if (n < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? WOLFSSL_CBIO_ERR_WANT_READ : WOLFSSL_CBIO_ERR_GENERAL;
    return static_cast<int>(n);
}

static int transmit(WOLFSSL *, char *bytes, int len, void *context) {
    auto *tls = static_cast<turtle_tls *>(context);
    const auto &h = tls->hooks;
    ssize_t n;
    do {
        h.transfer_begin(h.context, 1, static_cast<size_t>(len));
        n = send(tls->fd, bytes, static_cast<size_t>(len), MSG_NOSIGNAL);
        h.transfer_end(h.context, 1, static_cast<size_t>(len), n,
                       reinterpret_cast<const unsigned char *>(bytes));
    } while (n < 0 && errno == EINTR);
    if (n < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? WOLFSSL_CBIO_ERR_WANT_WRITE : WOLFSSL_CBIO_ERR_GENERAL;
    return static_cast<int>(n);
}

void turtle_tls_free(turtle_tls *tls) {
    if (!tls)
        return;
    if (tls->session)
        wolfSSL_free(tls->session);
    if (tls->context)
        wolfSSL_CTX_free(tls->context);
    delete tls;
}

static bool setup(turtle_tls *tls, const turtle_tls_config *config) {
    const bool server = config->role == TURTLE_SERVER;
    const bool verify_peer = !server || config->auth == TURTLE_MUTUAL_AUTH;
    tls->verifies_peer = verify_peer;
    tls->report_context = config->context;
    tls->report_session = config->report_session;
    tls->context = wolfSSL_CTX_new(server ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method());
    if (!tls->context)
        return false;
    if ((server || config->auth == TURTLE_MUTUAL_AUTH) &&
        (!config->cert_file || !config->key_file ||
         wolfSSL_CTX_use_certificate_chain_file(tls->context, config->cert_file) != WOLFSSL_SUCCESS ||
         wolfSSL_CTX_use_PrivateKey_file(tls->context, config->key_file, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS))
        return false;
    if (verify_peer &&
        (!config->ca_file || !config->server_name || !*config->server_name ||
         wolfSSL_CTX_load_verify_locations(tls->context, config->ca_file, nullptr) != WOLFSSL_SUCCESS))
        return false;
    wolfSSL_CTX_set_verify(tls->context, verify_peer ? WOLFSSL_VERIFY_PEER |
                           (server ? WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0) : WOLFSSL_VERIFY_NONE, nullptr);
    tls->session = wolfSSL_new(tls->context);
    if (!tls->session ||
        wolfSSL_set_fd(tls->session, tls->fd) != WOLFSSL_SUCCESS ||
        (server && wolfSSL_no_ticket_TLSv13(tls->session) != 0))
        return false;
    return !verify_peer ||
           wolfSSL_check_domain_name(tls->session, config->server_name) == WOLFSSL_SUCCESS;
}

struct Library {
    const int status = wolfSSL_Init();
    ~Library() {
        if (status == WOLFSSL_SUCCESS)
            wolfSSL_Cleanup();
    }
};

turtle_tls *turtle_tls_setup(const turtle_tls_config *config, int connected_fd) {
    static const Library library;
    auto *tls = new (std::nothrow) turtle_tls{};
    if (!tls)
        return nullptr;
    if (library.status != WOLFSSL_SUCCESS) {
        delete tls;
        return nullptr;
    }
    tls->fd = connected_fd;
    if (setup(tls, config))
        return tls;
    turtle_tls_free(tls);
    return nullptr;
}

turtle_status turtle_tls_set_hooks(turtle_tls *tls, const turtle_transport_hooks *hooks) {
    if (hooks && (!hooks->coverage || !hooks->transfer_begin || !hooks->transfer_end))
        return TURTLE_TLS_UNSUPPORTED;
    if (tls->hooks.coverage)
        tls->hooks.coverage(tls->hooks.context, 0);
    if (!hooks) {
        wolfSSL_SSLSetIORecv(tls->session, EmbedReceive);
        wolfSSL_SSLSetIOSend(tls->session, EmbedSend);
        tls->hooks = {};
        return wolfSSL_set_fd(tls->session, tls->fd) == WOLFSSL_SUCCESS ? TURTLE_TLS_OK : TURTLE_TLS_ERROR;
    }
    tls->hooks = *hooks;
    wolfSSL_SSLSetIORecv(tls->session, receive);
    wolfSSL_SSLSetIOSend(tls->session, transmit);
    wolfSSL_SetIOReadCtx(tls->session, tls);
    wolfSSL_SetIOWriteCtx(tls->session, tls);
    hooks->coverage(hooks->context, 1);
    return TURTLE_TLS_OK;
}

static turtle_status finish(turtle_tls *tls, int result) {
    if (result != WOLFSSL_SUCCESS)
        return TURTLE_TLS_ERROR;
    if (tls->reported)
        return TURTLE_TLS_OK;
    const bool v13 = wolfSSL_version(tls->session) == TLS1_3_VERSION;
    const bool resumed = wolfSSL_session_reused(tls->session) != 0;
#ifdef WOLFSSL_EARLY_DATA
    const bool early_data = wolfSSL_get_early_data_status(tls->session) == WOLFSSL_EARLY_DATA_ACCEPTED;
#else
    const bool early_data = false; // This build has no early-data code.
#endif
    if (!v13 || resumed || early_data)
        return TURTLE_TLS_ERROR;
    if (tls->report_session) {
        // This build need not retain the peer certificate. On a fresh
        // handshake, strict native verification rejects missing/invalid
        // peer certificates before the success return. In the unchecked
        // role we make no claim about certificate presence.
        const turtle_session_info facts{v13, resumed, early_data,
                                       tls->verifies_peer ? 1 : -1, tls->verifies_peer};
        tls->report_session(tls->report_context, &facts);
    }
    tls->reported = true;
    return TURTLE_TLS_OK;
}

turtle_status turtle_tls_connect(turtle_tls *tls) {
    return finish(tls, wolfSSL_connect(tls->session));
}

turtle_status turtle_tls_accept(turtle_tls *tls, const unsigned char *, size_t n) {
    if (n)
        return TURTLE_TLS_UNSUPPORTED;
    return finish(tls, wolfSSL_accept(tls->session));
}

ptrdiff_t turtle_app_send(turtle_tls *tls, const unsigned char *data, size_t len) {
    const int n = wolfSSL_write(tls->session, data, static_cast<int>(std::min(len, size_t{INT_MAX})));
    return n > 0 ? n : -1;
}

ptrdiff_t turtle_app_recv(turtle_tls *tls, unsigned char *data, size_t len) {
    const int n = wolfSSL_read(tls->session, data, static_cast<int>(std::min(len, size_t{INT_MAX})));
    if (n > 0)
        return n;
    return wolfSSL_get_error(tls->session, n) == WOLFSSL_ERROR_ZERO_RETURN ? 0 : -1;
}
