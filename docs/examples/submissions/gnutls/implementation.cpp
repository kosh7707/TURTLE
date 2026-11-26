#include <turtle/implementation.hpp>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <cerrno>
#include <cstdlib>
#include <initializer_list>
#include <cstring>
#include <new>
#include <sys/socket.h>

struct turtle_tls {
    gnutls_certificate_credentials_t credentials = nullptr;
    gnutls_session_t session = nullptr;
    gnutls_session_t early = nullptr;
    turtle_transport_hooks hooks{};
    gnutls_typed_vdata_st verification[2]{};
    char *peer = nullptr;
    int fd;
    bool client = false;
    bool client_complete = false;
};

static ssize_t receive(gnutls_transport_ptr_t context, void *bytes, size_t len) {
    auto *tls = static_cast<turtle_tls *>(context);
    ssize_t n;
    do {
        n = recv(tls->fd, bytes, len, 0);
    } while (n < 0 && errno == EINTR);
    if (n > 0 && tls->hooks.after_recv)
        tls->hooks.after_recv(tls->hooks.context, static_cast<const unsigned char *>(bytes), n);
    return n;
}

static ssize_t transmit(gnutls_transport_ptr_t context, const void *bytes, size_t len) {
    auto *tls = static_cast<turtle_tls *>(context);
    ssize_t n;
    do {
        if (tls->hooks.before_send)
            tls->hooks.before_send(tls->hooks.context, static_cast<const unsigned char *>(bytes), len);
        n = send(tls->fd, bytes, len, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    return n;
}

static ssize_t plain_receive(gnutls_transport_ptr_t context, void *bytes, size_t len) {
    return recv(static_cast<turtle_tls *>(context)->fd, bytes, len, 0);
}

static ssize_t plain_transmit(gnutls_transport_ptr_t context, const void *bytes, size_t len) {
    return send(static_cast<turtle_tls *>(context)->fd, bytes, len, MSG_NOSIGNAL);
}

void turtle_tls_free(turtle_tls *tls) {
    if (!tls)
        return;
    if (tls->early)
        gnutls_deinit(tls->early);
    if (tls->session)
        gnutls_deinit(tls->session);
    if (tls->credentials)
        gnutls_certificate_free_credentials(tls->credentials);
    std::free(tls->peer);
    gnutls_global_deinit();
    delete tls;
}

static bool setup_session(turtle_tls *tls, gnutls_session_t &session, bool server, bool early) {
    const unsigned mode = static_cast<unsigned>(server ? GNUTLS_SERVER : GNUTLS_CLIENT);
    const unsigned flags = mode | GNUTLS_NO_TICKETS | GNUTLS_NO_AUTO_SEND_TICKET |
                           GNUTLS_NO_SIGNAL | (early ? GNUTLS_ENABLE_EARLY_START : 0);
    if (gnutls_init(&session, flags) < 0 ||
        gnutls_priority_set_direct(session, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr) < 0 ||
        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, tls->credentials) < 0)
        return false;
    gnutls_transport_set_int(session, tls->fd);
    if (tls->peer) {
        if (server)
            gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
        else if (gnutls_server_name_set(session, GNUTLS_NAME_DNS, tls->peer, std::strlen(tls->peer)) < 0)
            return false;
        gnutls_session_set_verify_cert2(session, tls->verification, 2, 0);
    }
    return true;
}

static bool setup(turtle_tls *tls, const turtle_tls_config *config) {
    const bool server = config->role == TURTLE_SERVER;
    const bool mutual = config->auth == TURTLE_MUTUAL_AUTH;
    tls->client = !server;
    if (gnutls_certificate_allocate_credentials(&tls->credentials) < 0)
        return false;
    if (server || mutual) {
        if (!config->cert_file || !config->key_file ||
            gnutls_certificate_set_x509_key_file(tls->credentials, config->cert_file,
                                                config->key_file, GNUTLS_X509_FMT_PEM) < 0)
            return false;
    }
    if (!server || mutual) {
        if (!config->ca_file || !config->server_name || !*config->server_name ||
            gnutls_certificate_set_x509_trust_file(tls->credentials, config->ca_file, GNUTLS_X509_FMT_PEM) <= 0)
            return false;
        tls->peer = strdup(config->server_name);
        if (!tls->peer)
            return false;
        static unsigned char server_purpose[] = GNUTLS_KP_TLS_WWW_SERVER;
        static unsigned char client_purpose[] = GNUTLS_KP_TLS_WWW_CLIENT;
        tls->verification[0] = {GNUTLS_DT_DNS_HOSTNAME, reinterpret_cast<unsigned char *>(tls->peer), 0};
        tls->verification[1] = {GNUTLS_DT_KEY_PURPOSE_OID, server ? client_purpose : server_purpose, 0};
    }
    return setup_session(tls, tls->session, server, false) &&
           (!server || mutual || setup_session(tls, tls->early, true, true));
}

turtle_tls *turtle_tls_setup(const turtle_tls_config *config, int connected_fd) {
    auto *tls = new (std::nothrow) turtle_tls{};
    if (!tls)
        return nullptr;
    if (gnutls_global_init() < 0) {
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
    tls->hooks = hooks ? *hooks : turtle_transport_hooks{};
    for (auto session : {tls->session, tls->early}) {
        if (session) {
            gnutls_transport_set_ptr(session, tls);
            gnutls_transport_set_pull_function(session, hooks ? receive : plain_receive);
            gnutls_transport_set_push_function(session, hooks ? transmit : plain_transmit);
        }
    }
    return TURTLE_TLS_OK;
}

static turtle_status handshake(gnutls_session_t session) {
    int result;
    do {
        result = gnutls_handshake(session);
    } while (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED);
    return result == GNUTLS_E_SUCCESS ? TURTLE_TLS_OK : TURTLE_TLS_ERROR;
}

turtle_status turtle_tls_connect(turtle_tls *tls) {
    if (tls->client_complete)
        return TURTLE_TLS_OK;
    const auto result = handshake(tls->session);
    tls->client_complete = result == TURTLE_TLS_OK;
    return result;
}

static ptrdiff_t send_plain(gnutls_session_t session, const unsigned char *data, size_t len) {
    ssize_t n;
    do {
        n = gnutls_record_send(session, data, len);
    } while (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED);
    return n > 0 ? n : -1;
}

turtle_status turtle_tls_accept(turtle_tls *tls, const unsigned char *greeting, size_t len) {
    if (!len)
        return handshake(tls->session);
    if (!tls->early)
        return TURTLE_TLS_UNSUPPORTED;
    if (handshake(tls->early) != TURTLE_TLS_OK)
        return TURTLE_TLS_ERROR;
    if (!(gnutls_session_get_flags(tls->early) & GNUTLS_SFLAGS_EARLY_START))
        return TURTLE_TLS_UNSUPPORTED;
    while (len) {
        ptrdiff_t n = send_plain(tls->early, greeting, len);
        if (n < 0)
            return TURTLE_TLS_ERROR;
        greeting += n;
        len -= static_cast<size_t>(n);
    }
    if (handshake(tls->early) != TURTLE_TLS_OK)
        return TURTLE_TLS_ERROR;
    gnutls_deinit(tls->session);
    tls->session = tls->early;
    tls->early = nullptr;
    return TURTLE_TLS_OK;
}

ptrdiff_t turtle_app_send(turtle_tls *tls, const unsigned char *data, size_t len) {
    return send_plain(tls->session, data, len);
}

ptrdiff_t turtle_app_recv(turtle_tls *tls, unsigned char *data, size_t len) {
    if (tls->client && turtle_tls_connect(tls) != TURTLE_TLS_OK)
        return -1;
    ssize_t n;
    do {
        n = gnutls_record_recv(tls->session, data, len);
    } while (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED);
    return n >= 0 ? n : -1;
}
