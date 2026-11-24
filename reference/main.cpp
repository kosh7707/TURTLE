// Stock peer only. This program is never linked to the measured application.
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
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
#include <turtle/start.h>
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
void event(const char *name) { turtle_observe_event(name); }
struct Session {
  bool client, mutual;
  const char *peer;
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx{
      SSL_CTX_new(TLS_method()), SSL_CTX_free};
  std::unique_ptr<SSL, decltype(&SSL_free)> tls{nullptr, SSL_free};
  int fd = -1, gate = -1;
  bool saw_hello = false, hrr = false, paused = false;
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
      if (s.client && s.gate >= 0 && !s.paused) {
        s.paused = true;
        event("probe_paused"); // callback blocks before processing SH, hence
                               // before CF
        char release;
        ssize_t rc;
        do
          rc = read(s.gate, &release, 1);
        while (rc < 0 && errno == EINTR);
        if (rc != 1 || release != 'G')
          _exit(2);
        event("probe_resumed");
      }
    }
  }
  void handshake() {
    require(SSL_do_handshake(tls.get()) == 1, "handshake_failed");
    event("hs_complete");
    bool verify = client || mutual;
    bool verified = verify && SSL_get_verify_result(tls.get()) == X509_V_OK &&
                    SSL_get0_peer_certificate(tls.get());
    require(!verify || verified, "peer_authentication_failed");
    event("auth_accepted"); // local policy accepted; peer_verified remains
                            // false on a server not authenticating clients
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
  void send_message(const std::string &expected, bool early = false) {
    std::string data(expected.size(), '\0');
    require(fread(data.data(), 1, data.size(), stdin) == data.size() &&
                data == expected,
            "stdin_payload_mismatch");
    size_t i = 0;
    while (i < data.size()) {
      size_t n = 0;
      turtle_observe_plain("write_attempt", data.data() + i, data.size() - i);
      int rc =
          early ? SSL_write_early_data(tls.get(), data.data() + i,
                                       data.size() - i, &n)
                : SSL_write_ex(tls.get(), data.data() + i, data.size() - i, &n);
      require(rc == 1 && n > 0, "write_failed");
      turtle_observe_plain("write_accepted", data.data() + i, n);
      i += n;
    }
  }
  void receive_message(const std::string &expected) {
    std::string data(expected.size(), '\0');
    size_t i = 0;
    while (i < data.size()) {
      size_t n = 0;
      require(SSL_read_ex(tls.get(), data.data() + i, data.size() - i, &n) ==
                      1 &&
                  n > 0,
              "read_failed");
      turtle_observe_plain("read_return", data.data() + i, n);
      i += n;
    }
    require(data == expected, "plaintext_mismatch");
    turtle_observe_plain("validated", data.data(), i);
    require(fwrite(data.data(), 1, i, stdout) == i && fflush(stdout) == 0,
            "stdout_failed");
  }
  void run(int scenario) {
    bool greeting = scenario == 2 || scenario == 4,
         request = scenario == 1 || scenario >= 3, response = scenario >= 3;
    std::string cad = env("TURTLE_REQUEST", "ping"),
                sad1 = env("TURTLE_GREETING", "helo"),
                sad2 = env("TURTLE_RESPONSE", "pong");
    auto *bio = SSL_get_wbio(tls.get());
    require(bio && bio == SSL_get_rbio(tls.get()), "unexpected_peer_bio");
    BIO_set_callback_arg(bio, reinterpret_cast<char *>(this));
    BIO_set_callback_ex(bio, on_bio);
    observing = true;
    turtle_observe_coverage("library_io", 1);
    turtle_observe_coverage("header", 1);
    event("ready");
    require(turtle_wait_start() >= 0, "start_barrier_failed");
    event("hs_begin");
    if (!client && greeting) {
      char scratch;
      size_t bytes = 0;
      require(SSL_read_early_data(tls.get(), &scratch, 1, &bytes) ==
                      SSL_READ_EARLY_DATA_FINISH &&
                  bytes == 0 && !SSL_is_init_finished(tls.get()),
              "server_first_unavailable");
      event("hs_progress");
      send_message(sad1, true);
      turtle_observe_fact("server_first", 1);
    }
    handshake();
    if (client) {
      if (request)
        send_message(cad);
      if (greeting)
        receive_message(sad1);
      if (response)
        receive_message(sad2);
    } else {
      if (request)
        receive_message(cad);
      if (response)
        send_message(sad2);
    }
    turtle_observe_fact("application_only_tail", own_finished && clean_tail);
    event("end");
    observing = false;
    turtle_observe_coverage("library_io", 0);
    turtle_observe_coverage("header", 0);
    SSL_shutdown(tls.get()); // one close_notify; do not wait for peer shutdown
  }
};
} // namespace
int main(int argc, char **argv) try {
  signal(SIGPIPE, SIG_IGN);
  bool check = argc == 6 && argv[1] == "--role"sv && argv[3] == "--auth"sv &&
               argv[5] == "--check"sv;
  require(check || (argc == 7 && argv[1] == "--native-stream"sv),
          "expected --native-stream ROLE AUTH HOST PORT SCENARIO");
  std::string_view role = argv[2], auth = argv[check ? 4 : 3];
  require((role == "client" || role == "server") &&
              (auth == "mtls" || auth == "server"),
          "invalid_role_or_auth");
  Session peer(role == "client", auth == "mtls");
  if (check) {
    puts("{\"ready\":true}");
    return 0;
  }
  std::string_view scenario = argv[6];
  require(scenario.size() == 2 && scenario[0] == 'S' && scenario[1] >= '0' &&
              scenario[1] <= '4',
          "invalid_scenario");
  if (auto g = env("TURTLE_PROBE_GATE_FD")) {
    require(peer.client, "client_gate_only");
    peer.gate = number(g, INT_MAX);
  }
  peer.connect_to(argv[4], number(argv[5], 65535));
  peer.run(scenario[1] - '0');
  return 0;
} catch (const std::exception &e) {
  fprintf(stderr, "reference: %s\n", e.what());
  ERR_print_errors_fp(stderr);
  return 1;
}
