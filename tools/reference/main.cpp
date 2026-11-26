// Stock peer only. This program is never linked to the measured application.
#include <arpa/inet.h>
#include <climits>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <netinet/tcp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <turtle/observe.h>
#include <turtle/endpoint.h>
#include <unistd.h>

namespace {
using namespace std::string_view_literals;
void require(bool ok, const char *why) {
  if (!ok)
    throw std::runtime_error(why);
}
const char *env(const char *key, const char *fallback = nullptr) {
  const char *v = std::getenv(key);
  return v && *v ? v : fallback;
}
int number(std::string_view s, int max) {
  int n = 0;
  auto [p, e] = std::from_chars(s.begin(), s.end(), n);
  require(e == std::errc() && p == s.end() && n >= 0 && n <= max,
          "invalid_number");
  return n;
}
// Ask this OpenSSL build's providers which spelling corresponds to the IANA
// ID. The host does not translate any application's configuration.
std::string selected_group() {
  auto expected = env("TURTLE_EXPECTED_GROUP_ID");
  if (!expected)
    return "X25519";
  struct Group {
    unsigned id;
    char name[128]{};
  } group{unsigned(number(expected, 65535))};
  auto provider = [](OSSL_PROVIDER *p, void *state) {
    auto entry = [](const OSSL_PARAM params[], void *opaque) {
      auto &g = *static_cast<Group *>(opaque);
      unsigned id = 0;
      const char *name = nullptr;
      auto idp = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_ID);
      auto np = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME);
      if (idp && np && OSSL_PARAM_get_uint(idp, &id) && id == g.id &&
          OSSL_PARAM_get_utf8_string_ptr(np, &name) && name &&
          strlen(name) < sizeof(g.name))
        strcpy(g.name, name);
      return 1;
    };
    OSSL_PROVIDER_get_capabilities(p, "TLS-GROUP", entry, state);
    return 1;
  };
  require(OSSL_PROVIDER_do_all(nullptr, provider, &group) == 1 && group.name[0],
          "reference_group_unavailable");
  return group.name;
}
struct Session {
  bool client, mutual;
  const char *peer;
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx{
      SSL_CTX_new(TLS_method()), SSL_CTX_free};
  std::unique_ptr<SSL, decltype(&SSL_free)> tls{nullptr, SSL_free};
  int fd = -1;
  bool saw_hello = false, hrr = false;
  unsigned group = 0;
  bool own_finished = false, clean_tail = true, observing = false;
  uint64_t header_offset[2]{};
  turtle_observe_stamp io_begin[2]{};
  Session(bool c, bool m)
      : client(c), mutual(m),
        peer(env("TURTLE_PEER_NAME", c ? "localhost" : "client.turtle.test")) {
    require(ctx && SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) &&
                SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) &&
                SSL_CTX_set_num_tickets(ctx.get(), 0) &&
                SSL_CTX_set1_groups_list(ctx.get(), selected_group().c_str()),
            "tls_configuration");
    if (auto value = env("TURTLE_EXPECTED_SUITE_ID")) {
      auto id = number(value, 65535);
      const char *name = nullptr;
      auto ciphers = SSL_CTX_get_ciphers(ctx.get());
      for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
        auto candidate = sk_SSL_CIPHER_value(ciphers, i);
        if (SSL_CIPHER_get_protocol_id(candidate) == id) {
          name = SSL_CIPHER_get_name(candidate);
          break;
        }
      }
      require(name && SSL_CTX_set_ciphersuites(ctx.get(), name) == 1,
              "reference_suite_unavailable");
    }
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
    if (!client || mutual) {
      auto cert = env("TURTLE_CERT"), key = env("TURTLE_KEY");
      require(cert && key &&
                  SSL_CTX_use_certificate_chain_file(ctx.get(), cert) == 1 &&
                  SSL_CTX_use_PrivateKey_file(ctx.get(), key,
                                              SSL_FILETYPE_PEM) == 1 &&
                  SSL_CTX_check_private_key(ctx.get()) == 1,
              "certificate_configuration");
    }
    if (client || mutual) {
      auto ca = env("TURTLE_CA");
      require(ca && SSL_CTX_load_verify_locations(ctx.get(), ca, nullptr) == 1,
              "trust_configuration");
      SSL_CTX_set_verify(ctx.get(),
                         SSL_VERIFY_PEER |
                             (client ? 0 : SSL_VERIFY_FAIL_IF_NO_PEER_CERT),
                         nullptr);
    }
    tls.reset(SSL_new(ctx.get()));
    require(tls && SSL_set_block_padding(tls.get(), 0) == 1, "tls_allocation");
    if (client || mutual) {
      SSL_set_hostflags(tls.get(), X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
      require(SSL_set1_host(tls.get(), peer) == 1,
              "peer_identity_configuration");
    }
    if (client) {
      SSL_set_connect_state(tls.get());
      require(SSL_set_tlsext_host_name(tls.get(), peer) == 1, "sni");
    } else
      SSL_set_accept_state(tls.get());
    SSL_set_msg_callback(tls.get(), on_message);
    SSL_set_msg_callback_arg(tls.get(), this);
  }
  ~Session() {
    if (fd >= 0)
      close(fd);
  }
  void connect_to(const char *host, int port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    require(inet_pton(AF_INET, host, &addr.sin_addr) == 1,
            "numeric_ipv4_required");
    if (client) {
      fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      require(fd >= 0 && connect(fd, reinterpret_cast<sockaddr *>(&addr),
                                 sizeof(addr)) == 0,
              "connect");
    } else {
      int listener = -1;
      if (auto inherited = env("TURTLE_LISTEN_FD"))
        listener = number(inherited, INT_MAX);
      else {
        listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        require(listener >= 0 &&
                    bind(listener, reinterpret_cast<sockaddr *>(&addr),
                         sizeof(addr)) == 0 &&
                    listen(listener, 1) == 0,
                "listen");
      }
      fd = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
      close(listener);
      require(fd >= 0, "accept");
    }
    int yes = 1;
    require(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == 0 &&
                SSL_set_fd(tls.get(), fd) == 1,
            "socket_setup");
  }
  // Observe the existing socket BIO. These are library-I/O calls, not syscall
  // timestamps. Never modify transferred bytes, retry state or return values.
  static long on_bio(BIO *bio, int op, const char *buf, size_t len, int, long,
                     int result, size_t *done) {
    auto &s = *reinterpret_cast<Session *>(BIO_get_callback_arg(bio));
    int action = op & ~BIO_CB_RETURN;
    if (!s.observing || (action != BIO_CB_WRITE && action != BIO_CB_READ))
      return result;
    bool sent = action == BIO_CB_WRITE;
    if ((op & BIO_CB_RETURN) == 0)
      s.io_begin[sent] = turtle_observe_now();
    else {
      auto end = turtle_observe_now();
      turtle_observe_io(
          s.io_begin[sent], end, "library_io", sent, len,
          result > 0 && done ? static_cast<int64_t>(*done) : result, buf, 0);
    }
    return result;
  }
  static void on_message(int sent, int, int type, const void *buf, size_t n,
                         SSL *, void *arg) {
    auto &s = *static_cast<Session *>(arg);
    auto p = static_cast<const unsigned char *>(buf);
    if (s.observing && type == SSL3_RT_HEADER && n == 5) {
      turtle_observe_header(sent, s.header_offset[!!sent], p);
      s.header_offset[!!sent] += 5u + (unsigned(p[3]) << 8) + p[4];
    }
    if (s.observing && sent &&
        (type == SSL3_RT_ALERT || (type == SSL3_RT_HANDSHAKE && n))) {
      if (s.own_finished || type == SSL3_RT_ALERT)
        s.clean_tail = false;
      if (type == SSL3_RT_HANDSHAKE && p[0] == SSL3_MT_FINISHED)
        s.own_finished = true;
    }
    if (type != SSL3_RT_HANDSHAKE || n < 39 || p[0] != SSL3_MT_SERVER_HELLO ||
        (sent != 0) == s.client)
      return;
    static constexpr unsigned char retry[]{
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
        0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
        0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    if (!memcmp(p + 6, retry, sizeof(retry)))
      s.hrr = true;
    else {
      s.saw_hello = true;
      // TLS 1.3 ServerHello key_share extension contains the negotiated IANA
      // group.
      size_t i = 39 + p[38] + 3;
      auto u16 = [&](size_t j) { return (unsigned(p[j]) << 8) | p[j + 1]; };
      if (i + 2 <= n && i + 2 + u16(i) == n)
        for (i += 2; i + 4 <= n;) {
          unsigned t = u16(i), z = u16(i + 2);
          i += 4;
          if (i + z > n)
            break;
          if (t == TLSEXT_TYPE_key_share && z >= 4)
            s.group = u16(i);
          i += z;
        }
    }
  }
  bool peer_verified() const {
    return SSL_get_verify_result(tls.get()) == X509_V_OK &&
           SSL_get0_peer_certificate(tls.get()) != nullptr;
  }
  static turtle_result failed(SSL *ssl, int rc, const char *where) {
    const int error = SSL_get_error(ssl, rc);
    fprintf(stderr, "reference: %s (SSL error %d)\n", where, error);
    return error == SSL_ERROR_ZERO_RETURN ? TURTLE_CLOSED : TURTLE_ERROR;
  }
  static turtle_result handshake(void *conn, turtle_hs_point goal) {
    auto &s = *static_cast<Session *>(conn);
    SSL *ssl = s.tls.get();
    ERR_clear_error();
    if (goal == TURTLE_SERVER_CAN_SEND) {
      if (s.client)
        return TURTLE_UNSUPPORTED;
      char scratch;
      size_t n = 0;
      int rc = SSL_read_early_data(ssl, &scratch, 1, &n);
      if (rc == SSL_READ_EARLY_DATA_ERROR)
        return failed(ssl, 0, "handshake_failed");
      // The scenario does not admit client 0-RTT data.
      if (rc != SSL_READ_EARLY_DATA_FINISH || n)
        return TURTLE_ERROR;
      return SSL_is_init_finished(ssl) ? TURTLE_UNSUPPORTED : TURTLE_OK;
    }
    int rc = SSL_do_handshake(ssl);
    if (rc != 1)
      return failed(ssl, rc, "handshake_failed");
    if (!SSL_is_init_finished(ssl) ||
        ((s.client || s.mutual) && !s.peer_verified()))
      return TURTLE_ERROR;
    turtle_observe_event("auth_accepted");
    return TURTLE_OK;
  }
  static turtle_result write_plain(void *conn, turtle_hs_point at,
                                   const void *buf, size_t len, size_t *n) {
    auto *ssl = static_cast<Session *>(conn)->tls.get();
    ERR_clear_error();
    int rc = at == TURTLE_SERVER_CAN_SEND ? SSL_write_early_data(ssl, buf, len, n)
                                          : SSL_write_ex(ssl, buf, len, n);
    return rc == 1 ? TURTLE_OK : failed(ssl, rc, "write_failed");
  }
  static turtle_result read_plain(void *conn, void *buf, size_t cap, size_t *n) {
    auto *ssl = static_cast<Session *>(conn)->tls.get();
    ERR_clear_error();
    int rc = SSL_read_ex(ssl, buf, cap, n);
    return rc == 1 ? TURTLE_OK : failed(ssl, rc, "read_failed");
  }
  void report_negotiated() const {
    bool verify = client || mutual;
    bool verified = verify && peer_verified();
    turtle_observe_fact("verify_peer", verify);
    turtle_observe_fact("peer_verified", verified);
    turtle_observe_fact("hrr", saw_hello ? int(hrr) : -1);
    turtle_observe_fact("resumed", SSL_session_reused(tls.get()));
    turtle_observe_fact("early_data", SSL_get_early_data_status(tls.get()) ==
                                          SSL_EARLY_DATA_ACCEPTED);
    turtle_observe_fact("sender_unpadded", 1);
    turtle_observe_identity(
        SSL_version(tls.get()),
        SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(tls.get())), group,
        verified ? peer : nullptr);
  }
  void run() {
    auto *bio = SSL_get_wbio(tls.get());
    require(bio && bio == SSL_get_rbio(tls.get()), "unexpected_peer_bio");
    BIO_set_callback_arg(bio, reinterpret_cast<char *>(this));
    BIO_set_callback_ex(bio, on_bio);
    observing = true;
    turtle_observe_coverage("library_io", 1);
    turtle_observe_coverage("header", 1);
    const turtle_endpoint endpoint{this, handshake, write_plain, read_plain};
    auto result = turtle_run_endpoint(&endpoint);
    observing = false;
    turtle_observe_coverage("library_io", 0);
    turtle_observe_coverage("header", 0);
    if (SSL_is_init_finished(tls.get()))
      report_negotiated();
    turtle_observe_fact("application_only_tail", own_finished && clean_tail);
    require(result == TURTLE_OK, "endpoint_failed");
    SSL_shutdown(tls.get()); // one close_notify; do not wait for peer shutdown
  }
};
} // namespace
int main(int argc, char **argv) try {
  signal(SIGPIPE, SIG_IGN);
  bool check = argc == 6 && argv[1] == "--role"sv && argv[3] == "--auth"sv &&
               argv[5] == "--check"sv;
  require(check || (argc == 6 && argv[1] == "--native-stream"sv),
          "expected --native-stream ROLE AUTH HOST PORT");
  std::string_view role = argv[2], auth = argv[check ? 4 : 3];
  require((role == "client" || role == "server") &&
              (auth == "mtls" || auth == "server"),
          "invalid_role_or_auth");
  Session peer(role == "client", auth == "mtls");
  if (check) {
    puts("{\"ready\":true}");
    return 0;
  }
  require(env("TURTLE_ROLE", "") == role, "launcher_role_mismatch");
  peer.connect_to(argv[4], number(argv[5], 65535));
  peer.run();
  return 0;
} catch (const std::exception &e) {
  fprintf(stderr, "reference: %s\n", e.what());
  ERR_print_errors_fp(stderr);
  return 1;
}
