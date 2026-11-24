// Fault-only peer for testing a real server's reaction to missing
// authentication and a close_notify following just two authenticated request
// bytes.
#include <arpa/inet.h>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <openssl/ssl.h>
#include <string>
#include <unistd.h>
#include <vector>
int main(int argc, char **argv) {
  std::string port;
  bool check = false, short_request = false;
  int split = argc;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--") {
      split = i;
      break;
    }
    if (a == "--check")
      check = true;
    if (a == "--port" && i + 1 < argc)
      port = argv[++i];
  }
  if (split + 2 >= argc)
    return 2;
  short_request = std::string(argv[split + 2]) == "partial";
  if (check) {
    // The public readiness check is that of the unchanged, valid target.
    // Only the actual TLS connection is deliberately faulted below.
    argv[0] = argv[split + 1];
    argv[split + 1] = nullptr;
    ::execv(argv[0], argv);
    return 2;
  }
  auto ctx = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
      SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
  if (!ctx || !SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) ||
      !SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) ||
      !SSL_CTX_load_verify_locations(ctx.get(), std::getenv("TURTLE_CA"),
                                     nullptr))
    return 2;
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
  if (short_request &&
      (SSL_CTX_use_certificate_chain_file(ctx.get(),
                                          std::getenv("TURTLE_CERT")) != 1 ||
       SSL_CTX_use_PrivateKey_file(ctx.get(), std::getenv("TURTLE_KEY"),
                                   SSL_FILETYPE_PEM) != 1))
    return 2;
  auto s =
      std::unique_ptr<SSL, decltype(&SSL_free)>(SSL_new(ctx.get()), SSL_free);
  if (!s || !SSL_set1_host(s.get(), "localhost") ||
      !SSL_set1_groups_list(s.get(), "X25519"))
    return 2;
  int sock = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(std::stoi(port));
  if (sock < 0 || ::connect(sock, reinterpret_cast<sockaddr *>(&a), sizeof a) ||
      !SSL_set_fd(s.get(), sock))
    return 2;
  std::cout << "READY" << std::endl;
  std::string start;
  if (!std::getline(std::cin, start) || start != "START")
    return 2;
  if (SSL_connect(s.get()) == 1 && short_request) {
    if (SSL_write(s.get(), "pi", 2) != 2)
      return 2;
    SSL_shutdown(s.get()); // send close_notify, then wait for peer result
  }
  char response[16];
  if (SSL_read(s.get(), response, sizeof response) > 0)
    return 3;
  ::close(sock);
  return 1; // a deliberately incomplete client cannot submit a valid result
}
