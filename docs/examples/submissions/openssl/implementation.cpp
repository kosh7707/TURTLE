#include <cerrno>
#include <cstdio>
#include <new>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <turtle/implementation.hpp>
#include <turtle/observe.h>

struct turtle_tls {
  SSL_CTX *ctx;
  SSL *ssl;
  turtle_transport_hooks hooks;
  bool reported;
};

static bool present(const char *s) { return s && *s; }

static bool transfers(const turtle_transport_hooks &h) {
  return h.coverage && h.transfer_begin && h.transfer_end;
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
  if (transfers(h)) {
    if (!returning)
      h.transfer_begin(h.context, sent, size);
    else {
      // The return flag is a status; only *done describes accepted/returned
      // bytes. Never pass the requested length as an actual transfer.
      if (ret > 0 && (!done || *done > size || *done > PTRDIFF_MAX))
        h.coverage(h.context, -1);
      else {
        const ptrdiff_t result = ret > 0 ? static_cast<ptrdiff_t>(*done)
                                        : (ret < 0 ? -1 : 0);
        h.transfer_end(h.context, sent, size, result, bytes);
      }
    }
  } else if (bytes) {
    if (!returning && sent && h.before_send && size)
      h.before_send(h.context, bytes, size);
    if (returning && !sent && h.after_recv && ret > 0 && done && *done)
      h.after_recv(h.context, bytes, *done);
  }
  return ret;
}

static void finished_message(int sent, int version, int type, const void *data,
                             size_t size, SSL *, void *) {
  if (version == TLS1_3_VERSION && type == SSL3_RT_HANDSHAKE && size &&
      *static_cast<const unsigned char *>(data) == SSL3_MT_FINISHED) {
    // OpenSSL protocol-message callbacks are not ciphertext I/O timestamps.
    turtle_observe_event(sent ? "local_finished_message"
                              : "peer_finished_message");
  }
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
  auto *bio = SSL_get_rbio(t->ssl);
  if (!bio || bio != SSL_get_wbio(t->ssl))
    return TURTLE_TLS_UNSUPPORTED;
  if (transfers(t->hooks))
    t->hooks.coverage(t->hooks.context, 0);
  t->hooks = h ? *h : turtle_transport_hooks{};
  BIO_set_callback_arg(bio, h ? reinterpret_cast<char *>(t) : nullptr);
  BIO_set_callback_ex(bio, h ? observe : nullptr);
  SSL_set_msg_callback(t->ssl, h ? finished_message : nullptr);
  if (transfers(t->hooks))
    t->hooks.coverage(t->hooks.context, 1);
  return TURTLE_TLS_OK;
}

static bool again(SSL *ssl, int rc) {
  const int e = SSL_get_error(ssl, rc);
  return e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE ||
         (e == SSL_ERROR_SYSCALL && errno == EINTR);
}

static turtle_status failed(const char *operation) {
  std::fprintf(stderr, "OpenSSL %s failed\n", operation);
  ERR_print_errors_fp(stderr);
  return TURTLE_TLS_ERROR;
}

static turtle_status finish(turtle_tls *tls) {
  auto *ssl = tls->ssl;
  int rc;
  do {
    ERR_clear_error();
    rc = SSL_do_handshake(ssl);
  } while (rc <= 0 && again(ssl, rc));
  if (rc != 1 || !SSL_is_init_finished(ssl))
    return failed("handshake");
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
      (verify && !verified))
    return failed("session validation");
  tls->reported = true;
  turtle_observe_fact("resumed", resumed);
  turtle_observe_fact("early_data", early);
  turtle_observe_fact("verify_peer", verify);
  turtle_observe_fact("peer_cert_present", peer_cert);
  turtle_observe_fact("peer_verified", verified);
  turtle_observe_identity(SSL_version(ssl),
                          SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl)),
                          0, verified ? peer_name : nullptr);
  turtle_observe_event("auth_accepted");
  return TURTLE_TLS_OK;
}

turtle_status turtle_tls_connect(turtle_tls *t) { return finish(t); }

turtle_status turtle_tls_accept(turtle_tls *t, const unsigned char *greeting,
                                size_t len) {
  if (len) {
    if (!greeting)
      return TURTLE_TLS_ERROR;
    unsigned char scratch;
    size_t n = 0;
    int rc;
    do {
      ERR_clear_error();
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
      turtle_observe_plain("write_attempt", greeting, len);
      n = 0;
      ERR_clear_error();
      rc = SSL_write_early_data(t->ssl, greeting, len, &n);
      const auto returned = turtle_observe_now();
      if (rc != 1 && again(t->ssl, rc))
        continue;
      if (rc != 1 || !n || n > len)
        return failed("early greeting write");
      turtle_observe_plain_at(returned, "write_accepted", greeting, n);
      greeting += n;
      len -= n;
    }
    turtle_observe_fact("server_first", 1);
  }
  return finish(t);
}

ptrdiff_t turtle_app_send(turtle_tls *t, const unsigned char *p, size_t size) {
  size_t n = 0;
  int rc;
  do {
    ERR_clear_error();
    rc = SSL_write_ex(t->ssl, p, size, &n);
  } while (rc != 1 && again(t->ssl, rc));
  return rc == 1 ? static_cast<ptrdiff_t>(n) : -1;
}

ptrdiff_t turtle_app_recv(turtle_tls *t, unsigned char *p, size_t size) {
  size_t n = 0;
  int rc;
  do {
    ERR_clear_error();
    rc = SSL_read_ex(t->ssl, p, size, &n);
  } while (rc != 1 && again(t->ssl, rc));
  if (rc == 1)
    return static_cast<ptrdiff_t>(n);
  return SSL_get_error(t->ssl, rc) == SSL_ERROR_ZERO_RETURN ? 0 : -1;
}
