#include "config/config.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

namespace {
void require(bool condition, const char* reason) {
    if (!condition)
        throw std::runtime_error(reason);
}
turtle::config::Command parse(std::initializer_list<std::string> options) {
    std::vector<std::string> strings(options);
    std::vector<char*> argv;
    for (auto& string : strings)
        argv.push_back(string.data());
    return turtle::config::parse(static_cast<int>(argv.size()), argv.data());
}
bool rejects(std::initializer_list<std::string> options) {
    try {
        (void)parse(options);
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}
} // namespace
int main() {
    const auto dir =
        std::filesystem::temp_directory_path() / ("turtle-config-" + std::to_string(getpid()));
    try {
        std::filesystem::create_directory(dir);
        const auto path = (dir / "profile.json").string();
        std::ofstream(path)
            << R"({"name":"test","pki":"certs","tls":{"tickets":0,"mutual_auth":true},"measurement":{"samples":3,"connections":2}})";
        const auto a = parse({"turtle", "run", "--samples", "7", "--connections", "3",
                              "--profile", path, "--no-perf"})
                           .run;
        require(a.samples == 7 && a.connections == 3 && a.tls.mutual_auth && !a.perf,
                "CLI must override profile independent of order");
        require(a.tls.ca_file == (dir / "certs/ca.pem").string(),
                "credential path must be profile-relative");
        const auto b = parse({"turtle", "run", "--profile", path, "--samples", "9"}).run;
        require(b.connections == 2, "profile connection count was not applied");
        require(a.profile_hash == b.profile_hash,
                "measurement settings must not fragment profile identity");
        const auto c = parse({"turtle", "run", "--profile", path, "--tickets", "2"}).run;
        require(c.profile_hash != b.profile_hash, "TLS changes must affect profile identity");
        std::filesystem::create_directory(dir / "certs");
        std::ofstream(dir / "certs/ca.pem") << "first test certificate input";
        const auto first_input = parse({"turtle", "run", "--profile", path}).run.profile_hash;
        std::ofstream(dir / "certs/ca.pem") << "different test certificate input";
        require(parse({"turtle", "run", "--profile", path}).run.profile_hash != first_input,
                "different certificate bytes must affect profile identity");
        require(parse({"turtle", "--help"}).action == turtle::config::Command::Action::Help,
                "help action");
        require(parse({"turtle", "capabilities"}).action ==
                    turtle::config::Command::Action::Capabilities,
                "capabilities action");
        require(parse({"turtle", "run"}).run.connections == 1,
                "default connection count changed");
        require(parse({"turtle", "run", "--warmups", "1024", "--connections", "1"})
                        .run.connections == 1,
                "maximum combined connection count was rejected");
        require(turtle::config::usage().find("--connections N") != std::string::npos &&
                    turtle::config::usage().find("Warm-up connections") != std::string::npos,
                "help does not distinguish measured and warm-up connections");
        require(rejects({"turtle", "run", "--samples", "-1"}),
                "negative sample count accepted");
        require(rejects({"turtle", "run", "--connections", "0"}),
                "zero measured connections accepted");
        require(rejects({"turtle", "run", "--connections", "1026"}),
                "too many measured connections accepted");
        require(rejects(
                    {"turtle", "run", "--warmups", "1024", "--connections", "2"}),
                "too many combined connections accepted");
        require(parse({"turtle", "run"}).run.tls.cipher == "TLS_AES_128_GCM_SHA256",
                "fixed cipher suite default changed");
        require(parse({"turtle", "run", "--cipher", "TLS_AES_128_GCM_SHA256"}).run.tls.cipher ==
                    "TLS_AES_128_GCM_SHA256",
                "fixed cipher suite was rejected");
        for (const auto* cipher : {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
                                  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"}) {
            require(rejects({"turtle", "run", "--cipher", cipher}),
                    "out-of-scope cipher suite accepted");
            std::ofstream(path) << "{\"tls\":{\"cipher\":\"" << cipher << "\"}}";
            require(rejects({"turtle", "run", "--profile", path}),
                    "out-of-scope profile cipher accepted");
            require(parse({"turtle", "run", "--profile", path, "--cipher",
                           "TLS_AES_128_GCM_SHA256"}).run.tls.cipher ==
                        "TLS_AES_128_GCM_SHA256",
                    "explicit fixed cipher override was rejected");
        }
        std::filesystem::remove_all(dir);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        std::filesystem::remove_all(dir);
        return 1;
    }
}
