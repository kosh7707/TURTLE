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
};

static int receive(WOLFSSL *, char *bytes, int len, void *context) {
    auto *tls = static_cast<turtle_tls *>(context);
    ssize_t n;
    do {
        n = recv(tls->fd, bytes, static_cast<size_t>(len), 0);
    } while (n < 0 && errno == EINTR);
    if (n > 0 && tls->hooks.after_recv)
        tls->hooks.after_recv(tls->hooks.context, reinterpret_cast<const unsigned char *>(bytes), n);
    if (n == 0)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    if (n < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? WOLFSSL_CBIO_ERR_WANT_READ : WOLFSSL_CBIO_ERR_GENERAL;
    return static_cast<int>(n);
}

static int transmit(WOLFSSL *, char *bytes, int len, void *context) {
    auto *tls = static_cast<turtle_tls *>(context);
    ssize_t n;
    do {
        if (tls->hooks.before_send)
            tls->hooks.before_send(tls->hooks.context, reinterpret_cast<const unsigned char *>(bytes), len);
        n = send(tls->fd, bytes, static_cast<size_t>(len), MSG_NOSIGNAL);
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
    wolfSSL_Cleanup();
    delete tls;
}

static bool setup(turtle_tls *tls, const turtle_tls_config *config) {
    const bool server = config->role == TURTLE_SERVER;
    const bool verify_peer = !server || config->auth == TURTLE_MUTUAL_AUTH;
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

turtle_tls *turtle_tls_setup(const turtle_tls_config *config, int connected_fd) {
    auto *tls = new (std::nothrow) turtle_tls{};
    if (!tls)
        return nullptr;
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
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
    return TURTLE_TLS_OK;
}

turtle_status turtle_tls_connect(turtle_tls *tls) {
    return wolfSSL_connect(tls->session) == WOLFSSL_SUCCESS ? TURTLE_TLS_OK : TURTLE_TLS_ERROR;
}

turtle_status turtle_tls_accept(turtle_tls *tls, const unsigned char *, size_t n) {
    if (n)
        return TURTLE_TLS_UNSUPPORTED;
    return wolfSSL_accept(tls->session) == WOLFSSL_SUCCESS ? TURTLE_TLS_OK : TURTLE_TLS_ERROR;
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
