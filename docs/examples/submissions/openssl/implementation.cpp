#include <cerrno>
#include <cstdio>
#include <new>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <turtle/implementation.hpp>

// OpenSSL 2d1c10a592677ff34cdf60bd59c431d835a1fc26 reads precisely the
// outstanding header or body bytes on this socket path. Correlate native
// callbacks against the BIO receive count; the runner checks raw framing.
struct incoming_records {
  uint64_t received;
  uint64_t end;
  uint64_t finished_end;
  unsigned char outer;
  bool inner_handshake;
  bool active;
};

struct turtle_tls {
  SSL_CTX *ctx;
  SSL *ssl;
  turtle_transport_hooks hooks;
  void *context;
  decltype(turtle_tls_config::report_session) report_session;
  decltype(turtle_tls_config::greeting_written) greeting_written;
  incoming_records incoming;
  bool started;
  bool reported;
};

static bool present(const char *s) { return s && *s; }

static bool valid_record(int type, int version, size_t length) {
  switch (type) {
  case SSL3_RT_HANDSHAKE:
    return (version == TLS1_VERSION || version == TLS1_2_VERSION) &&
           length && length <= SSL3_RT_MAX_PLAIN_LENGTH;
  case SSL3_RT_CHANGE_CIPHER_SPEC:
    return version == TLS1_2_VERSION && length == 1;
  case SSL3_RT_APPLICATION_DATA:
    return version == TLS1_2_VERSION && length &&
           length <= SSL3_RT_MAX_TLS13_ENCRYPTED_LENGTH;
  default:
    return false;
  }
}

static void observe_message(int sent, int version, int type, const void *data,
                            size_t n, SSL *ssl, void *arg) {
  if (sent || !arg)
    return;
  auto &r = static_cast<turtle_tls *>(arg)->incoming;
  if (!r.active)
    return;
  const auto *p = static_cast<const unsigned char *>(data);
  if (type == SSL3_RT_HEADER) {
    if (!p || n != SSL3_RT_HEADER_LENGTH || r.received < r.end ||
        r.received - r.end != n ||
        (r.outer == SSL3_RT_APPLICATION_DATA && !r.inner_handshake)) {
      r.active = false;
      return;
    }
    const size_t length = (p[3] << 8) | p[4];
    if (length > UINT64_MAX - r.received ||
        version != ((p[1] << 8) | p[2]) ||
        !valid_record(p[0], version, length)) {
      r.active = false;
      return;
    }
    r.outer = p[0];
    r.inner_handshake = false;
    r.end = r.received + length; // received includes this record's header.
  } else if (type == SSL3_RT_INNER_CONTENT_TYPE) {
    if (!p || n != 1 || version != TLS1_3_VERSION || r.received != r.end ||
        r.outer != SSL3_RT_APPLICATION_DATA || r.inner_handshake ||
        p[0] != SSL3_RT_HANDSHAKE) {
      r.active = false;
      return;
    }
    r.inner_handshake = true;
  } else if (type == SSL3_RT_HANDSHAKE && p && n && p[0] == SSL3_MT_FINISHED) {
    // OpenSSL emits this after fragment collection, but BEFORE verifying
    // Finished. The most recent inner handshake record supplied its last byte.
    if (version != TLS1_3_VERSION || SSL_get_state(ssl) != TLS_ST_SR_FINISHED ||
        r.finished_end || r.received != r.end ||
        r.outer != SSL3_RT_APPLICATION_DATA || !r.inner_handshake) {
      r.active = false;
      return;
    }
    r.finished_end = r.end;
  }
}

static long observe(BIO *bio, int op, const char *data, size_t size, int, long,
                    int ret, size_t *done) {
  auto *tls = reinterpret_cast<turtle_tls *>(BIO_get_callback_arg(bio));
  const bool returning = (op & BIO_CB_RETURN) != 0;
  op &= ~BIO_CB_RETURN;
  if (!tls || (op != BIO_CB_READ && op != BIO_CB_WRITE))
    return ret;
  auto &h = tls->hooks;
  auto *bytes = reinterpret_cast<const unsigned char *>(data);
  const bool sent = op == BIO_CB_WRITE;
  const int saved_errno = errno;
  if (!returning) {
    h.transfer_begin(h.context, sent, size);
  } else if (ret > 0 && (!done || *done > size || *done > PTRDIFF_MAX)) {
    h.coverage(h.context, -1);
    tls->incoming.active = false;
  } else {
    // A positive BIO status is not a byte count; only *done is.
    const ptrdiff_t result = ret > 0 ? static_cast<ptrdiff_t>(*done) : ret;
    h.transfer_end(h.context, sent, size, result, bytes);
    auto &r = tls->incoming;
    if (!sent && result > 0 && r.active) {
      const auto n = static_cast<uint64_t>(result);
      if (!bytes || n > UINT64_MAX - r.received || r.finished_end)
        r.active = false;
      else
        r.received += n;
    }
  }
  errno = saved_errno;
  return ret;
}

static void stop_observing_messages(turtle_tls *t) {
  if (t->hooks.client_finished_record) {
    SSL_set_msg_callback(t->ssl, nullptr);
    SSL_set_msg_callback_arg(t->ssl, nullptr);
  }
  t->incoming = {};
}

void turtle_tls_free(turtle_tls *tls) {
  if (!tls)
    return;
  SSL_free(tls->ssl);
  SSL_CTX_free(tls->ctx);
  delete tls;
}

turtle_tls *turtle_tls_setup(const turtle_tls_config *c, int fd) {
  if (!c || fd < 0)
    return nullptr;
  auto *t = new (std::nothrow) turtle_tls{};
  if (!t)
    return nullptr;
  t->context = c->context;
  t->report_session = c->report_session;
  t->greeting_written = c->greeting_written;
  const bool server = c->role == TURTLE_SERVER;
  const bool verify = !server || c->auth == TURTLE_MUTUAL_AUTH;
  auto fail = [&]() -> turtle_tls * {
    ERR_print_errors_fp(stderr);
    turtle_tls_free(t);
    return nullptr;
  };
  t->ctx = SSL_CTX_new(TLS_method());
  if (!t->ctx || !SSL_CTX_set_min_proto_version(t->ctx, TLS1_3_VERSION) ||
      !SSL_CTX_set_max_proto_version(t->ctx, TLS1_3_VERSION) ||
      !SSL_CTX_set_num_tickets(t->ctx, 0))
    return fail();
  SSL_CTX_set_session_cache_mode(t->ctx, SSL_SESS_CACHE_OFF);
  if (server || c->auth == TURTLE_MUTUAL_AUTH) {
    if (!present(c->cert_file) || !present(c->key_file) ||
        SSL_CTX_use_certificate_chain_file(t->ctx, c->cert_file) != 1 ||
        SSL_CTX_use_PrivateKey_file(t->ctx, c->key_file, SSL_FILETYPE_PEM) !=
            1 ||
        !SSL_CTX_check_private_key(t->ctx))
      return fail();
  }
  if (verify) {
    if (!present(c->ca_file) || !present(c->server_name) ||
        !SSL_CTX_load_verify_locations(t->ctx, c->ca_file, nullptr))
      return fail();
    SSL_CTX_set_verify(t->ctx,
                       SSL_VERIFY_PEER |
                           (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
                       nullptr);
  }
  t->ssl = SSL_new(t->ctx);
  if (!t->ssl || !SSL_set_fd(t->ssl, fd))
    return fail();
  if (server)
    SSL_set_accept_state(t->ssl);
  else
    SSL_set_connect_state(t->ssl);
  if (verify) {
    auto *param = SSL_get0_param(t->ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    if (!X509_VERIFY_PARAM_set1_host(param, c->server_name, 0))
      return fail();
    if (!server && !SSL_set_tlsext_host_name(t->ssl, c->server_name))
      return fail();
  }
  return t;
}

turtle_status turtle_tls_set_hooks(turtle_tls *t,
                                   const turtle_transport_hooks *h) {
  if (h && (!h->coverage || !h->transfer_begin || !h->transfer_end))
    return TURTLE_TLS_UNSUPPORTED;
  auto *bio = SSL_get_rbio(t->ssl);
  if (!bio || bio != SSL_get_wbio(t->ssl))
    return TURTLE_TLS_UNSUPPORTED;
  if (t->hooks.coverage)
    t->hooks.coverage(t->hooks.context, 0);
  stop_observing_messages(t);
  t->hooks = h ? *h : turtle_transport_hooks{};
  BIO_set_callback_arg(bio, h ? reinterpret_cast<char *>(t) : nullptr);
  BIO_set_callback_ex(bio, h ? observe : nullptr);
  if (h && h->client_finished_record && !t->started && SSL_is_server(t->ssl) &&
      BIO_method_type(bio) == BIO_TYPE_SOCKET && !BIO_next(bio) &&
      !(SSL_get_options(t->ssl) & SSL_OP_ENABLE_KTLS) && !BIO_get_ktls_recv(bio) &&
      !SSL_get_read_ahead(t->ssl) && !SSL_get_max_early_data(t->ssl) &&
      SSL_set_max_pipelines(t->ssl, 1) == 1 &&
      SSL_set_msg_callback_arg(t->ssl, t) == 1) {
    t->incoming.active = true;
    SSL_set_msg_callback(t->ssl, observe_message);
  }
  if (h)
    t->hooks.coverage(t->hooks.context, 1);
  return TURTLE_TLS_OK;
}

static bool again(SSL *ssl, int rc) {
  const int saved_errno = errno;
  const int e = SSL_get_error(ssl, rc);
  errno = saved_errno;
  if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK ||
      saved_errno == ETIMEDOUT)
    return false;
  return e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE ||
         (e == SSL_ERROR_SYSCALL && saved_errno == EINTR);
}

static turtle_status failed(const char *operation) {
  const int saved_errno = errno;
  std::fprintf(stderr, "OpenSSL %s failed\n", operation);
  ERR_print_errors_fp(stderr);
  errno = saved_errno;
  return TURTLE_TLS_ERROR;
}

static turtle_status finish(turtle_tls *tls) {
  auto *ssl = tls->ssl;
  tls->started = true;
  int rc;
  do {
    ERR_clear_error();
    errno = 0;
    rc = SSL_do_handshake(ssl);
  } while (rc <= 0 && again(ssl, rc));
  if (rc != 1 || !SSL_is_init_finished(ssl)) {
    tls->incoming.active = false;
    return failed("handshake");
  }
  if (tls->reported)
    return TURTLE_TLS_OK;
  const bool resumed = SSL_session_reused(ssl);
  const bool early = SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_ACCEPTED;
  const bool verify = (SSL_get_verify_mode(ssl) & SSL_VERIFY_PEER) != 0;
  const bool peer_cert = SSL_get0_peer_certificate(ssl) != nullptr;
  const char *peer_name = SSL_get0_peername(ssl);
  const bool verified = verify && peer_cert && present(peer_name) &&
                        SSL_get_verify_result(ssl) == X509_V_OK;
  if (SSL_version(ssl) != TLS1_3_VERSION || resumed || early ||
      (verify && !verified)) {
    tls->incoming.active = false;
    return failed("session validation");
  }
  const bool observed = tls->incoming.active &&
                        SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_NOT_SENT;
  const uint64_t finished_end = observed ? tls->incoming.finished_end : 0;
  stop_observing_messages(tls);
  tls->reported = true;
  if (finished_end)
    tls->hooks.client_finished_record(tls->hooks.context, finished_end);
  if (tls->report_session) {
    const turtle_session_info facts{1, resumed, early, peer_cert, verified};
    tls->report_session(tls->context, &facts);
  }
  return TURTLE_TLS_OK;
}

turtle_status turtle_tls_connect(turtle_tls *t) { return finish(t); }

turtle_status turtle_tls_accept(turtle_tls *t, const unsigned char *greeting,
                                size_t len) {
  t->started = true;
  if (len) {
    if (!greeting)
      return TURTLE_TLS_ERROR;
    unsigned char scratch;
    size_t n = 0;
    int rc;
    do {
      ERR_clear_error();
      errno = 0;
      rc = SSL_read_early_data(t->ssl, &scratch, 1, &n);
    } while (rc == SSL_READ_EARLY_DATA_ERROR && again(t->ssl, 0));
    if (rc != SSL_READ_EARLY_DATA_FINISH || n)
      return failed("greeting handshake");
    // In TLS 1.3 this state follows the server Finished flight, before
    // processing the client Finished. Refuse to send at a different state.
    if (SSL_get_state(t->ssl) != TLS_ST_EARLY_DATA ||
        SSL_is_init_finished(t->ssl))
      return TURTLE_TLS_UNSUPPORTED;
    while (len) {
      n = 0;
      ERR_clear_error();
      errno = 0;
      rc = SSL_write_early_data(t->ssl, greeting, len, &n);
      if (rc != 1 && again(t->ssl, rc))
        continue;
      if (rc != 1 || !n || n > len)
        return failed("early greeting write");
      if (t->greeting_written)
        t->greeting_written(t->context, greeting, n);
      greeting += n;
      len -= n;
    }
  }
  return finish(t);
}

ptrdiff_t turtle_app_send(turtle_tls *t, const unsigned char *p, size_t size) {
  t->started = true;
  size_t n = 0;
  int rc;
  do {
    ERR_clear_error();
    errno = 0;
    rc = SSL_write_ex(t->ssl, p, size, &n);
  } while (rc != 1 && again(t->ssl, rc));
  return rc == 1 ? static_cast<ptrdiff_t>(n) : -1;
}

ptrdiff_t turtle_app_recv(turtle_tls *t, unsigned char *p, size_t size) {
  t->started = true;
  size_t n = 0;
  int rc;
  do {
    ERR_clear_error();
    errno = 0;
    rc = SSL_read_ex(t->ssl, p, size, &n);
  } while (rc != 1 && again(t->ssl, rc));
  if (rc == 1)
    return static_cast<ptrdiff_t>(n);
  return SSL_get_error(t->ssl, rc) == SSL_ERROR_ZERO_RETURN ? 0 : -1;
}
