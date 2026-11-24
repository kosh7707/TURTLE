// A separate, ordinary TLS client closes after a request prefix, or sends a
// wrong suffix. Inspect the server result as well as what the peer received:
// neither timing luck nor a client's successful write counts as evidence.
#include "artifact/json.hpp"
#include "process/process.hpp"
#include <arpa/inet.h>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
namespace fs = std::filesystem;
using namespace turtle::process;
namespace {
void require(bool ok, const char *reason) {
  if (!ok)
    throw std::runtime_error(reason);
}
void cert(const std::string &cli, const fs::path &dir,
          const std::string &name) {
  Args args{cli,
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-days",
            "1",
            "-config",
            "/dev/null",
            "-subj",
            "/CN=" + (name == "no-san" || name == "other.turtle.test"
                          ? "client.turtle.test"
                          : name),
            "-keyout",
            (dir / (name + ".key")).string(),
            "-out",
            (dir / (name + ".pem")).string()};
  if (name != "no-san")
    args.insert(
        args.end(),
        {"-addext", "subjectAltName=DNS:" +
                        (name == "client" ? "client.turtle.test" : name)});
  require(command(args).at("returncode") == 0, "certificate_generation_failed");
}
void trial(const std::string &cli, const std::string &ep, const fs::path &root,
           const std::string &scenario, const std::string &bytes,
           const std::string &identity = "client") {
  auto dir = root / (scenario + "-" + bytes + "-" + identity);
  fs::create_directories(dir);
  auto path = [&](const std::string &name) { return (root / name).string(); };
  // Pass a live listener so discovery cannot consume the only connection.
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t len = sizeof(addr);
  require(fd >= 0 &&
              bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ==
                  0 &&
              listen(fd, 1) == 0 &&
              getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0,
          "listener");
  std::string port = std::to_string(ntohs(addr.sin_port));
  // Preserve the exact plaintext reads: a generic endpoint error alone cannot
  // show that the deliberately malformed bytes actually reached the test.
  auto evidence = dir / "server.ndjson";
  int trace = open(evidence.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
  require(trace >= 0, "create_evidence");
  Environment env{
      {"TURTLE_EVIDENCE_FD", std::to_string(trace)},      {"TURTLE_LISTEN_FD", std::to_string(fd)},
      {"TURTLE_ROLE", "server"},
      {"TURTLE_SCENARIO", scenario},
      {"TURTLE_REQUEST", "ping"},
      {"TURTLE_CA",
       path((identity == "missing" ? "client" : identity) + ".pem")},
      {"TURTLE_CERT", path("localhost.pem")},
      {"TURTLE_KEY", path("localhost.key")},
      {"TURTLE_PEER_NAME", "client.turtle.test"},
      {"TURTLE_GREETING", "hello\n"},
      {"TURTLE_RESPONSE", "wrongly-sent-response\n"}};
  Child server(
      {ep, "--native-stream", "server", "mtls", "127.0.0.1", port},
      env, dir / "server.stderr");
  close(trace);
  close(fd);
  server.send((scenario == "S4" ? std::string("hello\n") : "") +
              "wrongly-sent-response\n");
  server.close_input();
  auto end = deadline(12);
  Args args{cli,
            "s_client",
            "-quiet",
            "-no_ign_eof",
            "-tls1_3",
            "-groups",
            "X25519",
            "-verify_return_error",
            "-verify_hostname",
            "localhost",
            "-CAfile",
            path("localhost.pem"),
            "-connect",
            "127.0.0.1:" + port};
  if (identity != "missing")
    args.insert(args.end(), {"-cert", path(identity + ".pem"), "-key",
                             path(identity + ".key")});
  Child client(args, {}, dir / "client.stderr");
  if (scenario == "S4")
    require(client.line(end) == "hello", "greeting_missing");
  client.send(bytes);
  client.close_input();
  auto output = client.collect(end);
  client.wait(end);
  require(output.empty(), "premature_response_received");
  require(server.wait(end) != 0, "incomplete_or_incorrect_request_accepted");
  require(server.collect(end).empty(),
          "unauthenticated_or_wrong_request_published");
  std::ifstream records(evidence);
  std::string line, received;
  bool rejected_before_application = identity != "client";
  while (std::getline(records, line)) {
    const auto event = turtle::artifact::Json::parse(line);
    if (event.at("kind") == "plain" && event.at("name") == "read_return")
      received += event.at("hex").get<std::string>();
    if (event.at("kind") == "plain")
      require(event.at("name") != "validated", "wrong_request_validated");
  }
  const char *expected = rejected_before_application ? ""
                         : bytes == "pi" ? "7069" : "70697878";
  require(received == expected, "unexpected_decrypted_request");
  if (rejected_before_application)
    require(server.errors().find("handshake_failed") != std::string::npos,
            "expected_tls_authentication_failure");
}
} // namespace
int main(int argc, char **argv) {
  try {
    require(argc == 4, "usage: partial_request OPENSSL ENDPOINT OUTPUT");
    auto root = fs::absolute(argv[3]);
    fs::create_directories(root);
    fs::path run;
    for (unsigned n = 0;; ++n) {
      run = root / ("run-" + std::to_string(n));
      if (fs::create_directory(run))
        break;
    }
    cert(argv[1], run, "localhost");
    cert(argv[1], run, "client");
    cert(argv[1], run, "other.turtle.test");
    cert(argv[1], run, "no-san");
    for (auto scenario : {"S3", "S4"})
      for (auto bytes : {"pi", "pixx"})
        trial(argv[1], argv[2], run, scenario, bytes);
    for (auto identity : {"other.turtle.test", "no-san", "missing"})
      trial(argv[1], argv[2], run, "S3", "ping", identity);
    std::cout << "S3/S4 mTLS servers withheld responses to incomplete and "
                 "invalid requests\n";
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
