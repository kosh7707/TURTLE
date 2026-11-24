// Independent installed-SDK client fixture: TLS, BIO and socket belong to app.
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <turtle/role.h>
#include <unistd.h>
struct App {
  turtle_session *ep;
  turtle_io_hooks counts{};
  int fd = -1;
  bool bytes_only = false;
  size_t calls = 0;
};
static int io(BIO *b, void *p, int size, bool tx) {
  auto &a = *static_cast<App *>(BIO_get_data(b));
  BIO_clear_retry_flags(b);
  for (;;) {
    // Deliberately vary fragment sizes on each syscall, including header
    // splits.
    auto n = std::min<size_t>(size, 1 + (a.calls++ * 5) % 19);
    if (tx && a.counts.before_send)
      a.counts.before_send(a.counts.context);
    if (!a.bytes_only && turtle_socket_before(a.ep, tx, p, n) < 0)
      return -1;
    auto rc = tx ? send(a.fd, p, n, MSG_NOSIGNAL | MSG_DONTWAIT)
                 : recv(a.fd, p, n, MSG_DONTWAIT);
    const int saved = errno;
    if (!a.bytes_only) {
      if (turtle_socket_returned(a.ep, rc) < 0 || errno != saved)
        std::abort();
    } else if (rc > 0 && turtle_session_wire(a.ep, tx, p, rc) < 0)
      std::abort();
    if (!tx && rc > 0 && a.counts.after_receive)
      a.counts.after_receive(a.counts.context);
    if (rc < 0 && saved == EINTR)
      continue;
    if (rc < 0 && (saved == EAGAIN || saved == EWOULDBLOCK)) {
      if (tx)
        BIO_set_retry_write(b);
      else
        BIO_set_retry_read(b);
    }
    errno = saved;
    return static_cast<int>(rc);
  }
}
int main(int argc, char **argv) {
  App a{turtle_session_open(argc, argv, "external-owned-fd", 0, 0)};
  if (!a.ep)
    return 1;
  const auto &cfg = *turtle_session_config(a.ep);
  a.bytes_only = cfg.argc == 1 && !strcmp(cfg.argv[0], "bytes-only");
  turtle_io_boundary counts{&a, [](void *p, turtle_io_hooks h) {
                              static_cast<App *>(p)->counts = h;
                            }};
  bool ok = cfg.role == TURTLE_CLIENT &&
            turtle_session_bind_counts(a.ep, &counts) == 1;
  if (!cfg.check) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg.port);
    a.fd = socket(AF_INET, SOCK_STREAM, 0);
    ok = ok && inet_pton(AF_INET, cfg.host, &addr.sin_addr) == 1 &&
         connect(a.fd, (sockaddr *)&addr, sizeof(addr)) == 0 &&
         turtle_session_attach(a.ep, a.fd) == 1;
  }
  auto ctx = SSL_CTX_new(TLS_method());
  const char *ca = getenv("TURTLE_CA"), *cert = getenv("TURTLE_CERT"),
             *key = getenv("TURTLE_KEY");
  ok = ok && ctx && ca &&
       SSL_CTX_load_verify_locations(ctx, ca, nullptr) == 1 &&
       SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
       SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1 &&
       SSL_CTX_set1_groups_list(ctx, "X25519") == 1;
  if (cfg.mutual_auth)
    ok = ok && cert && key &&
         SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) == 1 &&
         SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 1;
  auto ssl = ctx ? SSL_new(ctx) : nullptr;
  auto meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "app-owned");
  ok = ok && ssl && SSL_set1_host(ssl, "localhost") == 1 && meth &&
       BIO_meth_set_ctrl(meth,
                         [](BIO *, int cmd, long, void *) -> long {
                           return cmd == BIO_CTRL_FLUSH;
                         }) == 1 &&
       BIO_meth_set_read(meth, [](BIO *b, char *p,
                                  int n) { return io(b, p, n, false); }) == 1 &&
       BIO_meth_set_write(meth, [](BIO *b, const char *p, int n) {
         return io(b, const_cast<char *>(p), n, true);
       }) == 1;
  if (ok) {
    auto b = BIO_new(meth);
    ok = b != nullptr;
    if (b) {
      BIO_set_data(b, &a);
      BIO_set_init(b, 1);
      SSL_set_bio(ssl, b, b);
      SSL_set_connect_state(ssl);
      SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);
    }
  }
  if (turtle_session_ready(a.ep, ok) == 1) {
    turtle_action action;
    while (turtle_pull(a.ep, &action) == 1 && action.op != TURTLE_DONE) {
      int rc = -1;
      size_t n = 0;
      ERR_clear_error();
      turtle_before(a.ep);
      switch (action.op) {
      case TURTLE_HS:
        rc = SSL_do_handshake(ssl);
        break;
      case TURTLE_READ:
        rc = SSL_read_ex(ssl, action.in, action.size, &n);
        break;
      case TURTLE_WRITE:
        rc = SSL_write_ex(ssl, action.out, action.size, &n);
        break;
      case TURTLE_SHUTDOWN:
        rc = SSL_shutdown(ssl);
        break;
      default:
        std::abort();
      }
      turtle_returned(a.ep);
      auto e = rc > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl, rc);
      turtle_result r{e == SSL_ERROR_NONE          ? TURTLE_OK
                      : e == SSL_ERROR_WANT_READ   ? TURTLE_AGAIN_READ
                      : e == SSL_ERROR_WANT_WRITE  ? TURTLE_AGAIN_WRITE
                      : e == SSL_ERROR_ZERO_RETURN ? TURTLE_EOF
                                                   : TURTLE_ERROR,
                      n, 0};
      turtle_handshake_info f{};
      bool facts = rc == 1 && action.op == TURTLE_HS;
      if (facts)
        f = {static_cast<uint16_t>(SSL_version(ssl)),
             SSL_session_reused(ssl),
             SSL_get_cipher_name(ssl),
             "X25519",
             cfg.mutual_auth ? TURTLE_PROFILE_MTLS_1RTT
                             : TURTLE_PROFILE_SERVER_AUTH_1RTT,
             SSL_get0_peer_certificate(ssl) != nullptr &&
                 SSL_get_verify_result(ssl) == X509_V_OK,
             TURTLE_UNPADDED_APPLICATION_TAIL};
      if (turtle_submit(a.ep, r, facts ? &f : nullptr) < 0)
        break;
    }
  }
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  BIO_meth_free(meth);
  if (a.fd != -1)
    close(a.fd);
  return turtle_session_close(a.ep);
}
