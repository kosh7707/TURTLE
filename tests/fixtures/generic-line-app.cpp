// Test-only line chat application. No TURTLE actions, scenario names, or
// message IDs. The same executable also works without an observation sink.
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#ifdef OBSERVE
#include <turtle/observe.h>
#include <turtle/start.h>
#define REPORT(x) (x)
#define STAMP(n) const auto n = turtle_observe_now()
#else
#define REPORT(x) ((void)0)
#define STAMP(n) ((void)0)
#endif
namespace {
void need(bool ok, const char *what) {
  if (!ok)
    throw std::runtime_error(what);
}
void tls(int rc) {
  if (rc < 0)
    throw std::runtime_error(gnutls_strerror(rc));
}
int socket_for(bool server, const char *host, const char *port) {
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(std::stoi(port));
  need(inet_pton(AF_INET, host, &addr.sin_addr) == 1, "bad address");
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  need(fd >= 0, "socket");
  if (!server) {
    need(connect(fd, (sockaddr *)&addr, sizeof addr) == 0, "connect");
    return fd;
  }
  need(bind(fd, (sockaddr *)&addr, sizeof addr) == 0 && listen(fd, 1) == 0,
       "listen");
  int peer = accept(fd, nullptr, nullptr);
  close(fd);
  need(peer >= 0, "accept");
  return peer;
}
// The application's transport always suppresses SIGPIPE on socket writes.
// Observe the existing syscall, not a count inferred from a TLS return.
struct Channel {
  int fd;
  bool established = false, writing = false, clean_tail = true,
       sent_finished = false;
  std::string record;
};
int outgoing_handshake(gnutls_session_t session, unsigned type, unsigned,
                       unsigned incoming, const gnutls_datum_t *) {
  if (!incoming) {
    auto &c = *static_cast<Channel *>(gnutls_transport_get_ptr(session));
    if (c.sent_finished)
      c.clean_tail = false;
    if (type == GNUTLS_HANDSHAKE_FINISHED)
      c.sent_finished = true;
  }
  return 0;
}
ssize_t send_bytes(gnutls_transport_ptr_t arg, const void *p, size_t len) {
  STAMP(a);
  auto &c = *static_cast<Channel *>(arg);
  auto n = send(c.fd, p, len, MSG_NOSIGNAL);
  STAMP(b);
  REPORT(turtle_observe_io(a, b, "socket", 1, len, n, p, 0));
  if (c.established && n > 0) {
    if (c.writing)
      c.record.append(static_cast<const char *>(p), n);
    else
      c.clean_tail = false;
  }
  return n;
}
ssize_t recv_bytes(gnutls_transport_ptr_t arg, void *p, size_t len) {
  STAMP(a);
  auto n = recv(static_cast<Channel *>(arg)->fd, p, len, 0);
  STAMP(b);
  REPORT(turtle_observe_io(a, b, "socket", 0, len, n, p, 0));
  return n;
}
void say(gnutls_session_t session, std::string_view line) {
  while (!line.empty()) {
    // Small fragments exercise a real sequence of record sends/receives.
    auto n = std::min<size_t>(3, line.size());
    REPORT(turtle_observe_plain("write_attempt", line.data(), n));
    auto &c = *static_cast<Channel *>(gnutls_transport_get_ptr(session));
    c.record.clear();
    c.writing = true;
    auto rc = gnutls_record_send(session, line.data(), n);
    STAMP(done);
    c.writing = false;
    // This positive native application send must account for exactly one
    // unpadded protected record. Partial/would-block emissions cannot attest.
    if (rc > 0) {
      const auto tag = gnutls_cipher_get_tag_size(gnutls_cipher_get(session));
      const auto *h = reinterpret_cast<const unsigned char *>(c.record.data());
      auto total = c.record.size();
      c.clean_tail &= total == size_t(rc) + 6 + tag && total >= 5 &&
                      h[0] == 23 && h[1] == 3 && h[2] == 3 &&
                      ((size_t(h[3]) << 8) | h[4]) + 5 == total;
    } else if (!c.record.empty())
      c.clean_tail = false;
    if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN)
      continue;
    tls(rc);
    need(rc > 0, "empty write");
    REPORT(turtle_observe_plain_at(done, "write_accepted", line.data(), rc));
    line.remove_prefix(rc);
  }
}
void chat(gnutls_session_t session, int fd) {
  std::string partial;
  for (;;) {
    pollfd p[] = {{STDIN_FILENO, POLLIN, 0}, {fd, POLLIN, 0}};
    bool pending = gnutls_record_check_pending(session) > 0;
    int n = poll(p, 2, pending ? 0 : -1);
    if (n < 0 && errno == EINTR)
      continue;
    need(n >= 0, "poll");
    if (p[0].revents & (POLLIN | POLLHUP)) {
      std::array<char, 1024> input;
      ssize_t size = read(STDIN_FILENO, input.data(), input.size());
      if (size < 0 && errno == EINTR)
        continue;
      need(size >= 0, "read stdin");
      if (!size)
        break;
      say(session, {input.data(), size_t(size)});
    }
    if (pending || p[1].revents & (POLLIN | POLLHUP)) {
      char buf[2];
      auto rc = gnutls_record_recv(session, buf, sizeof buf);
      STAMP(done);
      if (rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED)
        continue;
      tls(rc);
      if (!rc)
        break;
      REPORT(turtle_observe_plain_at(done, "read_return", buf, rc));
      for (int i = 0; i < rc; ++i) {
        partial += buf[i];
        need(partial.size() <= 64, "oversized command");
        if (buf[i] != '\n')
          continue;
        need(partial == "PING/1\n" || partial == "PONG/1\n" ||
                 partial == "HELLO/1\n",
             "invalid command");
        REPORT(
            turtle_observe_plain("validated", partial.data(), partial.size()));
        need(fwrite(partial.data(), 1, partial.size(), stdout) ==
                     partial.size() &&
                 fflush(stdout) == 0,
             "stdout");
        partial.clear();
      }
    }
  }
  need(partial.empty(), "partial command");
}
int run(int argc, char **av) {
  need(argc == 8,
       "usage: chat client|server IP PORT CA CERT KEY EXPECTED_PEER");
  bool server = std::string_view(av[1]) == "server", verify = av[7][0] != '\0';
  need(server || std::string_view(av[1]) == "client", "bad role");
  need(verify || server, "server identity required");
  int fd = socket_for(server, av[2], av[3]);
  gnutls_certificate_credentials_t cred;
  tls(gnutls_certificate_allocate_credentials(&cred));
  if (verify)
    need(gnutls_certificate_set_x509_trust_file(cred, av[4],
                                                GNUTLS_X509_FMT_PEM) > 0,
         "no trust anchors");
  if (*av[5])
    tls(gnutls_certificate_set_x509_key_file(cred, av[5], av[6],
                                             GNUTLS_X509_FMT_PEM));
  gnutls_session_t session;
  tls(gnutls_init(&session, (server ? GNUTLS_SERVER : GNUTLS_CLIENT) |
                                GNUTLS_NO_TICKETS | GNUTLS_NO_AUTO_SEND_TICKET |
                                GNUTLS_NO_AUTO_REKEY));
  tls(gnutls_priority_set_direct(
      session, "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519",
      nullptr));
  tls(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred));
  if (server)
    gnutls_certificate_server_set_request(session, verify ? GNUTLS_CERT_REQUIRE
                                                          : GNUTLS_CERT_IGNORE);
  if (verify)
    gnutls_session_set_verify_cert(session, av[7], 0);
  Channel channel{};
  channel.fd = fd;
  gnutls_transport_set_ptr(session, &channel);
  gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
                                     GNUTLS_HOOK_POST, outgoing_handshake);
  gnutls_transport_set_pull_function(session, recv_bytes);
  gnutls_transport_set_push_function(session, send_bytes);
  REPORT(turtle_observe_coverage("socket", 1));
  REPORT(turtle_observe_event("ready"));
  REPORT(need(turtle_wait_start() >= 0, "start barrier"));
  REPORT(turtle_observe_event("hs_begin"));
  int rc;
  do {
    rc = gnutls_handshake(session);
  } while (rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED);
  STAMP(hs);
  tls(rc);
  REPORT(turtle_observe_event_at(hs, "hs_complete"));
  if (verify)
    need(gnutls_session_get_verify_cert_status(session) == 0,
         "peer verification failed");
  REPORT(turtle_observe_event("auth_accepted"));
  REPORT(turtle_observe_fact("verify_peer", verify));
  if (verify)
    REPORT(turtle_observe_fact("peer_verified", 1));
  REPORT(
      turtle_observe_fact("resumed", gnutls_session_is_resumed(session) != 0));
  // Early data was never enabled; verify the negotiated flag too.
  REPORT(turtle_observe_fact("early_data", (gnutls_session_get_flags(session) &
                                            GNUTLS_SFLAGS_EARLY_DATA) != 0));
  // Wire decoding, not a table mapping vendor constants, provides suite/group.
  REPORT(turtle_observe_identity(
      gnutls_protocol_get_version(session) == GNUTLS_TLS1_3 ? 0x304 : 0, 0, 0,
      verify ? av[7] : nullptr));
  channel.established = true;
  chat(session, fd);
  if (channel.clean_tail && channel.sent_finished) {
    REPORT(turtle_observe_fact("sender_unpadded", 1));
    REPORT(turtle_observe_fact("application_only_tail", 1));
  }
  REPORT(turtle_observe_event("end"));
  REPORT(turtle_observe_coverage("socket", 0));
  gnutls_bye(session, GNUTLS_SHUT_WR);
  gnutls_deinit(session);
  gnutls_certificate_free_credentials(cred);
  close(fd);
  return 0;
}
} // namespace
int main(int argc, char **av) {
  try {
    return run(argc, av);
  } catch (const std::exception &e) {
    fprintf(stderr, "chat: %s\n", e.what());
    return 1;
  }
}
