// A separate, ordinary TLS client closes after a request prefix, or sends a
// wrong suffix. Inspect the server result as well as what the peer received:
// neither timing luck nor a client's successful write counts as evidence.
#include "artifact/json.hpp"
#include "process/process.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
namespace fs = std::filesystem;
using namespace turtle::process;
namespace {
void require(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
void cert(const std::string& cli, const fs::path& dir, const std::string& name) {
    Args args{cli, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-noenc", "-days", "1", "-config", "/dev/null", "-subj",
        "/CN=" + (name == "no-san" || name == "other.turtle.test" ? "client.turtle.test" : name),
        "-keyout", (dir/(name+".key")).string(), "-out", (dir/(name+".pem")).string()};
    if (name != "no-san")
        args.insert(args.end(), {"-addext", "subjectAltName=DNS:" + (name == "client" ? "client.turtle.test" : name)});
    auto result = command(args);
    require(result.at("returncode") == 0, "certificate_generation_failed");
}
void trial(const std::string& cli, const std::string& ep, const fs::path& root,
           const std::string& scenario, const std::string& bytes,
           const std::string& identity = "client") {
    auto dir = root / (scenario + "-" + bytes + "-" + identity);
    fs::create_directories(dir);
    auto path = [&](const std::string& name) { return (root/name).string(); };
    Child server({ep, "--controlled", "--role", "server", "--port", "0", "--output", dir.string(),
        "--auth", "mtls", "--scenario", scenario, "--measured-role", "server", "--timeout", "5",
        "--greeting", "hello\n", "--response", "wrongly-sent-response\n", "--",
        "--ca", path((identity == "missing" ? "client" : identity) + ".pem"),
        "--cert", path("localhost.pem"), "--key", path("localhost.key")},
        {},dir/"server.stderr");
    auto end = deadline(12);
    auto listening = server.line(end);
    require(listening.starts_with("LISTEN "), "listen_failed");
    Args args{cli, "s_client", "-quiet", "-no_ign_eof", "-tls1_3", "-groups", "X25519",
        "-verify_return_error", "-verify_hostname", "localhost", "-CAfile", path("localhost.pem"),
        "-connect", "127.0.0.1:"+listening.substr(7)};
    if (identity != "missing")
        args.insert(args.end(), {"-cert", path(identity + ".pem"), "-key", path(identity + ".key")});
    Child client(args, {}, dir/"client.stderr");
    require(server.line(end) == "READY", "server_prepare_failed");
    server.send("START\n");
    server.close_input();
    if (scenario == "S4") require(client.line(end) == "hello", "greeting_missing");
    client.send(bytes);
    client.close_input();
    auto output = client.collect(end);
    client.wait(end);
    require(output.empty(), "premature_response_received");
    require(server.wait(end) != 0, "incomplete_or_incorrect_request_accepted");
    auto result = turtle::artifact::load(dir/"endpoint.json");
    const auto& task = result.at("scenario");
    if (identity != "client") {
        require(result.at("status") == "invalid" && task.at("content_verified") == false &&
                task.at("plaintext_sent") == 0 && task.at("plaintext_received") == 0,
                "server_accepted_unauthenticated_client");
        return;
    }
    require(result.at("status") == "invalid" && task.at("content_verified") == false &&
        task.at("plaintext_received") == bytes.size() &&
        task.at("plaintext_sent") == (scenario == "S4" ? 6 : 0), "server_sent_before_complete_request_validation");
    require(result.at("invalid_reason") == (bytes.size() < 4 ? "application_read_failed" : "application_content_mismatch"),
            "unexpected_server_error");
}
}
int main(int argc, char** argv) {
    try {
        require(argc == 4, "usage: partial_request OPENSSL ENDPOINT OUTPUT");
        auto root = fs::absolute(argv[3]);
        fs::create_directories(root);
        fs::path run;
        for (unsigned n = 0;; ++n) {
            run = root / ("run-" + std::to_string(n));
            if (fs::create_directory(run)) break;
        }
        cert(argv[1], run, "localhost");
        cert(argv[1], run, "client");
        cert(argv[1], run, "other.turtle.test");
        cert(argv[1], run, "no-san");
        for (auto scenario : {"S3", "S4"}) for (auto bytes : {"pi", "pixx"})
            trial(argv[1], argv[2], run, scenario, bytes);
        for (auto identity : {"other.turtle.test", "no-san", "missing"})
            trial(argv[1], argv[2], run, "S3", "ping", identity);
        std::cout << "S3/S4 mTLS servers withheld responses to incomplete and invalid requests\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
