#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <turtle/role.h>
#include <unistd.h>
#include <vector>

namespace {
void must(bool x) {
  if (!x)
    throw std::runtime_error("role test failed");
}
struct Tcp {
  int a = -1, b = -1;
  Tcp() {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    must(l >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    must(bind(l, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0 &&
         listen(l, 1) == 0);
    socklen_t len = sizeof(addr);
    must(getsockname(l, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    a = socket(AF_INET, SOCK_STREAM, 0);
    must(connect(a, reinterpret_cast<sockaddr *>(&addr), len) == 0);
    b = accept(l, nullptr, nullptr);
    close(l);
    must(b >= 0);
    must(send(b, "x", 1, 0) == 1);
  }
  ~Tcp() {
    close(a);
    close(b);
  }
};
enum Fault { good, corrupt, unknown_peer, missing_facts };
void test(const char *role, const char *scenario, Fault fault, bool short_io) {
  bool client = std::string(role) == "client", early = scenario[1] == '4',
       request = scenario[1] != '0';
  bool staged = client && scenario[1] == '3' && !short_io;
  char path[] = "/tmp/turtle-role-test-XXXXXX";
  must(mkdtemp(path));
  std::vector<std::string> args = {"tester",
                                   "--role",
                                   role,
                                   "--scenario",
                                   scenario,
                                   "--auth",
                                   "mtls",
                                   "--output",
                                   path,
                                   "--controlled",
                                   "--measured-role",
                                   role,
                                   "--app-chunk",
                                   short_io ? "3" : "0"};
  std::vector<char *> argv;
  for (auto &a : args)
    argv.push_back(a.data());
  Tcp tcp;
  auto *s = turtle_session_open(argv.size(), argv.data(),
                                "unchanged-native-app", 0, 1);
  must(s);
  must(turtle_session_attach(s, tcp.a) == 1);
  turtle_io_hooks hooks{};
  turtle_io_boundary boundary{&hooks, [](void *p, turtle_io_hooks h) {
                                *static_cast<turtle_io_hooks *>(p) = h;
                              }};
  must(turtle_session_bind_counts(s, &boundary) == 1);
  std::istringstream control("START\n");
  auto *buf = std::cin.rdbuf(control.rdbuf());
  must(turtle_session_ready(s, 1) == 1);
  bool retried = false, did_read = false, interleaved = false, wrote = false,
       rejected = false;
  size_t input_at = 0, write_at = 0;
  std::string input = client ? (early ? "helopong" : "pong") : "ping";
  turtle_action pending{};
  for (unsigned i = 0; i < 64; ++i) {
    turtle_action a{};
    must(turtle_pull(s, &a) == 1);
    if (a.op == TURTLE_DONE)
      break;
    turtle_handshake_info info{TURTLE_TLS13,
                               0,
                               "suite",
                               "group",
                               TURTLE_PROFILE_MTLS_1RTT,
                               fault == unknown_peer ? -1 : 1,
                               0};
    auto *f = a.op == TURTLE_HS && fault != missing_facts ? &info : nullptr;
    turtle_result r{TURTLE_OK, 0, 0};
    errno = EALREADY;
    turtle_before(s);
    must(errno == EALREADY);
    if (a.op == TURTLE_HS) {
      hooks.before_send(hooks.context);
      hooks.after_receive(hooks.context);
    }
    if (a.op == TURTLE_WRITE) {
      must(client || did_read);
      wrote = true;
      if (staged && !write_at) {
        must(a.size == 4 && memcmp(a.out, "ping", 4) == 0);
        r.bytes = 2;
        write_at = 2;
        hooks.before_send(hooks.context);
      } else if (!retried && !pending.out) {
        if (staged)
          must(a.size == 2 && memcmp(a.out, "ng", 2) == 0);
        pending = a;
        r.status = TURTLE_AGAIN_WRITE;
        r.allow_other = early && client;
      } else {
        if (!retried) {
          must(a.out == pending.out && a.size == pending.size);
          retried = true;
        }
        if (staged)
          must(a.size == 2 && memcmp(a.out, "ng", 2) == 0);
        r.bytes = short_io ? 1 : a.size;
        write_at += r.bytes;
        hooks.before_send(hooks.context);
      }
    } else if (a.op == TURTLE_READ) {
      did_read = true;
      if (early && pending.out && !retried)
        interleaved = true;
      r.bytes = short_io ? 1 : a.size;
      must(input_at + r.bytes <= input.size());
      memcpy(a.in, input.data() + input_at, r.bytes);
      input_at += r.bytes;
      if (fault == corrupt)
        static_cast<char *>(a.in)[0] = 'X';
      hooks.after_receive(hooks.context);
    } else if (a.op == TURTLE_FIRST_WRITE) {
      r.bytes = a.size;
      hooks.before_send(hooks.context);
    }
    errno = ENOTTY;
    turtle_returned(s);
    must(errno == ENOTTY);
    if (turtle_submit(s, r, f) != 1) {
      rejected = true;
      break;
    }
  }
  std::cin.rdbuf(buf);
  if (fault != good) {
    must(rejected && !wrote);
  } else {
    must(!rejected);
    if (request && client)
      must(retried && write_at == 4);
    if (early && client)
      must(interleaved && input_at == 8);
  }
  must((turtle_session_close(s) == 0) == (fault == good));
  must(!hooks.before_send);
  std::filesystem::remove_all(path);
}
} // namespace
void probe_client(bool complete) {
  char path[] = "/tmp/turtle-role-probe-XXXXXX";
  must(mkdtemp(path));
  std::vector<std::string> args = {
      "tester", "--role",       "client",          "--scenario",
      "S2",     "--purpose",    "capability",      "--output",
      path,     "--controlled", "--measured-role", "server"};
  std::vector<char *> argv;
  for (auto &a : args)
    argv.push_back(a.data());
  Tcp tcp;
  auto *s = turtle_session_open(argv.size(), argv.data(), "probe", 0, 0);
  must(s);
  must(turtle_session_attach(s, tcp.a) == 1);
  turtle_transport t{};
  must(turtle_session_transport(s, &t) == 1);
  std::istringstream control("START\nRESUME 1\n");
  auto *old = std::cin.rdbuf(control.rdbuf());
  must(turtle_session_ready(s, 1) == 1);
  turtle_action a{};
  must(turtle_pull(s, &a) == 1 && a.op == TURTLE_HS);
  turtle_before(s);
  // Reconstruct a handshake spanning two plaintext records and multiple
  // lower sends. A valid record prefix is not proof of a complete hello.
  const unsigned char first[] = {22, 3, 3, 0, 3, 1, 0, 0};
  std::vector<unsigned char> last = {22, 3, 3, 0, 51, 50, 3, 3};
  last.resize(last.size() + 32); // random
  for (unsigned char b : {0, 0, 2, 19, 1, 1, 0, 0, 7, 0, 43, 0, 3, 2, 3, 4})
    last.push_back(b);
  must(t.send(t.state, first, 2) == 2 &&
       t.send(t.state, first + 2, sizeof(first) - 2) == sizeof(first) - 2);
  if (complete)
    must(t.send(t.state, last.data(), last.size()) ==
         static_cast<ptrdiff_t>(last.size()));
  turtle_returned(s);
  must((turtle_submit(s, {TURTLE_AGAIN_READ, 0, 0}, nullptr) == 1) == complete);
  if (complete) {
    must(turtle_pull(s, &a) == 1 && a.op == TURTLE_HS);
    turtle_before(s);
    turtle_returned(s);
    turtle_handshake_info f{TURTLE_TLS13,
                            0,
                            "suite",
                            "group",
                            TURTLE_PROFILE_SERVER_AUTH_1RTT,
                            1,
                            0};
    must(turtle_submit(s, {TURTLE_OK, 0, 0}, &f) == 1);
    must(turtle_pull(s, &a) == 1 && a.op == TURTLE_READ);
    turtle_before(s);
    memcpy(a.in, "helo", 4);
    turtle_returned(s);
    must(turtle_submit(s, {TURTLE_OK, 4, 0}, nullptr) == 1);
    must(turtle_pull(s, &a) == 1 && a.op == TURTLE_SHUTDOWN);
    turtle_before(s);
    turtle_returned(s);
    must(turtle_submit(s, {TURTLE_OK, 0, 0}, nullptr) == 1);
  }
  std::cin.rdbuf(old);
  must((turtle_session_close(s) == 0) == complete);
  std::filesystem::remove_all(path);
}
int main() {
  probe_client(false);
  probe_client(true);
  for (const char *role : {"client", "server"})
    for (const char *scenario : {"S0", "S3", "S4"})
      for (bool partial : {false, true})
        test(role, scenario, good, partial);
  test("server", "S3", unknown_peer, false);
  test("server", "S3", missing_facts, false);
  test("server", "S3", corrupt, true);
}
