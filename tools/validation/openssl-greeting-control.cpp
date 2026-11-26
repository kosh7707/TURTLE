#include <turtle/implementation.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
constexpr std::string_view greeting = "turtle-greeting";

void require(bool ok, const char *reason) {
  if (!ok)
    throw std::runtime_error(reason);
}

struct Keys {
  std::string ca, server_cert, server_key, client_cert, client_key;
  bool mutual;
};

int server(const Keys &keys, int socket) {
  const turtle_tls_config config{
      TURTLE_SERVER, keys.mutual ? TURTLE_MUTUAL_AUTH : TURTLE_SERVER_AUTH,
      keys.ca.c_str(), keys.server_cert.c_str(), keys.server_key.c_str(),
      keys.mutual ? "client.turtle.test" : ""};
  std::unique_ptr<turtle_tls, decltype(&turtle_tls_free)> tls(
      turtle_tls_setup(&config, socket), turtle_tls_free);
  if (!tls ||
      turtle_tls_accept(tls.get(),
                        reinterpret_cast<const unsigned char *>(greeting.data()),
                        greeting.size()) != TURTLE_TLS_OK)
    return 1;
  std::puts("server: submitted accept(greeting) completed");
  return 0;
}

void send_all(int socket, std::string_view bytes) {
  while (!bytes.empty()) {
    const auto n = send(socket, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR)
      continue;
    require(n > 0, "send");
    bytes.remove_prefix(n);
  }
}

void receive(int socket, BIO *reader) {
  std::array<char, 16384> bytes{};
  ssize_t n;
  do {
    n = recv(socket, bytes.data(), bytes.size(), 0);
  } while (n < 0 && errno == EINTR);
  require(n > 0 && BIO_write(reader, bytes.data(), n) == n, "receive");
}

struct ClientFlight {
  size_t bytes = 0, record_start = 0, record_end = 0;
  size_t cert_end = 0, verify_end = 0, finished_start = 0, finished_end = 0;
  size_t finished_message_size = 0;
  unsigned finishes = 0;
  unsigned record_type = 0;
  bool finished_is_protected = false;

  static void observe(int sent, int version, int type, const void *buf, size_t n,
                      SSL *, void *opaque) {
    if (!sent || !n)
      return;
    auto &f = *static_cast<ClientFlight *>(opaque);
    auto p = static_cast<const unsigned char *>(buf);
    if (type == SSL3_RT_HEADER && n == 5) {
      f.record_type = p[0];
      f.record_start = f.bytes;
      f.bytes += 5 + (static_cast<unsigned>(p[3]) << 8) + p[4];
      f.record_end = f.bytes;
    } else if (version == TLS1_3_VERSION && type == SSL3_RT_HANDSHAKE) {
      if (*p == SSL3_MT_CERTIFICATE)
        f.cert_end = f.record_end;
      if (*p == SSL3_MT_CERTIFICATE_VERIFY)
        f.verify_end = f.record_end;
      if (*p == SSL3_MT_FINISHED) {
        ++f.finishes;
        f.finished_start = f.record_start;
        f.finished_end = f.record_end;
        f.finished_message_size = n;
        f.finished_is_protected = f.record_type == SSL3_RT_APPLICATION_DATA;
      }
    }
  }
};

std::string drain(BIO *writer) {
  std::string bytes(BIO_ctrl_pending(writer), '\0');
  size_t n = 0;
  if (!bytes.empty())
    require(BIO_read_ex(writer, bytes.data(), bytes.size(), &n) == 1 &&
                n == bytes.size(),
            "drain client TLS records");
  return bytes;
}

void client(const Keys &keys, int socket) {
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
      SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
  require(ctx && SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) &&
              SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) &&
              SSL_CTX_load_verify_locations(ctx.get(), keys.ca.c_str(), nullptr),
          "TLS client context");
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
  if (keys.mutual)
    require(SSL_CTX_use_certificate_chain_file(ctx.get(), keys.client_cert.c_str()) ==
                    1 &&
                SSL_CTX_use_PrivateKey_file(ctx.get(), keys.client_key.c_str(),
                                            SSL_FILETYPE_PEM) == 1,
            "TLS client credential");

  ClientFlight flight;
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
  require(ssl && X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl.get()),
                                            "localhost", 0) &&
              SSL_set_tlsext_host_name(ssl.get(), "localhost"),
          "TLS client setup");
  X509_VERIFY_PARAM_set_hostflags(SSL_get0_param(ssl.get()),
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
  auto *reader = BIO_new(BIO_s_mem());
  auto *writer = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl.get(), reader, writer);
  require(reader && writer, "memory BIO setup");
  SSL_set_connect_state(ssl.get());
  SSL_set_msg_callback(ssl.get(), ClientFlight::observe);
  SSL_set_msg_callback_arg(ssl.get(), &flight);

  size_t forwarded = 0;
  std::string held;
  while (true) {
    ERR_clear_error();
    const int rc = SSL_do_handshake(ssl.get());
    const int error = SSL_get_error(ssl.get(), rc);
    auto pending = drain(writer);
    if (rc != 1) {
      require(error == SSL_ERROR_WANT_READ && !flight.finishes,
              "handshake before Finished");
      send_all(socket, pending);
      forwarded += pending.size();
      receive(socket, reader);
      continue;
    }
    require(SSL_version(ssl.get()) == TLS1_3_VERSION &&
                !SSL_session_reused(ssl.get()) &&
                SSL_get_verify_result(ssl.get()) == X509_V_OK &&
                SSL_get0_peer_certificate(ssl.get()),
            "client did not negotiate a full, authenticated TLS 1.3 session");
    const auto suite =
        SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl.get()));
    // The default AES-GCM and ChaCha20-Poly1305 TLS 1.3 suites have
    // 16-byte tags. An unpadded, unmixed record is header + message + type + tag.
    require((suite == 0x1301 || suite == 0x1302 || suite == 0x1303) &&
                flight.finishes == 1 && flight.finished_is_protected &&
                flight.finished_end - flight.finished_start ==
                    5 + flight.finished_message_size + 1 + 16 &&
                forwarded <= flight.finished_start &&
                forwarded + pending.size() == flight.finished_end &&
                flight.finished_end == flight.bytes,
            "cannot isolate exactly the Finished record");
    require(keys.mutual ? flight.cert_end > 0 &&
                              flight.cert_end < flight.verify_end &&
                              flight.verify_end <= flight.finished_start
                        : !flight.cert_end && !flight.verify_end,
            "wrong client authentication flight");
    const size_t prefix = flight.finished_start - forwarded;
    held = pending.substr(prefix);
    const auto *header = reinterpret_cast<const unsigned char *>(held.data());
    require(held.size() >= 5 && header[0] == SSL3_RT_APPLICATION_DATA &&
                header[1] == 3 && header[2] == 3 &&
                held.size() == 5u + (static_cast<unsigned>(header[3]) << 8) +
                                   header[4],
            "actual withheld bytes do not match the protected record");
    send_all(socket, std::string_view(pending).substr(0, prefix));
    std::printf("client: TLS1.3, resumed=false, suite=0x%04x\n",
                static_cast<unsigned>(suite));
    std::printf("client: forwarded=%zu certificate_end=%zu verify_end=%zu; "
                "withheld only CF record [%zu,%zu) (%zu bytes)\n",
                flight.finished_start, flight.cert_end, flight.verify_end,
                flight.finished_start, flight.finished_end, held.size());
    break;
  }

  std::string received(greeting.size(), '\0');
  size_t used = 0;
  while (used != received.size()) {
    size_t n = 0;
    ERR_clear_error();
    const int rc = SSL_read_ex(ssl.get(), received.data() + used,
                               received.size() - used, &n);
    const int error = SSL_get_error(ssl.get(), rc);
    require(BIO_ctrl_pending(writer) == 0, "unexpected client TLS output");
    if (rc == 1) {
      require(n > 0 && n <= received.size() - used, "unexpected greeting size");
      used += n;
    } else {
      require(error == SSL_ERROR_WANT_READ, "client greeting read");
      receive(socket, reader);
    }
  }
  require(received == greeting, "greeting content");
  std::printf("client: validated SAD1 before CF release: %zu bytes, %s\n",
              received.size(), received.c_str());
  std::puts("client: releasing CF record");
  std::fflush(stdout);
  send_all(socket, held);
}
} // namespace

int main(int argc, char **argv) {
  if (argc != 3 || (std::string_view(argv[2]) != "server" &&
                    std::string_view(argv[2]) != "mtls"))
    return 2;
  const std::string dir = argv[1];
  const Keys keys{dir + "/ca.crt", dir + "/server.crt", dir + "/server.key",
                  dir + "/client.crt", dir + "/client.key",
                  std::string_view(argv[2]) == "mtls"};
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0)
    return 1;
  const timeval limit{4, 0};
  for (auto fd : sockets)
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) != 0)
      return 1;
  const auto pid = fork();
  if (pid < 0)
    return 1;
  if (pid == 0) {
    close(sockets[0]);
    const int result = server(keys, sockets[1]);
    close(sockets[1]);
    std::fflush(stdout);
    _exit(result);
  }
  close(sockets[1]);
  bool passed = false;
  try {
    client(keys, sockets[0]);
    passed = true;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "client: %s\n", e.what());
    ERR_print_errors_fp(stderr);
  }
  close(sockets[0]);
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  return passed && waited == pid && WIFEXITED(status) &&
                 WEXITSTATUS(status) == 0
             ? 0
             : 1;
}
