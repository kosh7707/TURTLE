#include "config/config.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

namespace {
void require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
turtle::config::Command parse(std::initializer_list<std::string> options) {
    std::vector<std::string> strings(options);
    std::vector<char*> argv;
    for (auto& string : strings) argv.push_back(string.data());
    return turtle::config::parse(static_cast<int>(argv.size()), argv.data());
}
}
int main() {
    const auto dir = std::filesystem::temp_directory_path() / ("turtle-config-" + std::to_string(getpid()));
    try {
        std::filesystem::create_directory(dir);
        const auto path = (dir / "profile.json").string();
        std::ofstream(path) << R"({"name":"test","pki":"certs","tls":{"tickets":0,"mutual_auth":true},"measurement":{"samples":3}})";
        const auto a = parse({"turtle", "run", "--samples", "7", "--profile", path, "--no-perf"}).run;
        require(a.samples == 7 && a.tls.mutual_auth && !a.perf, "CLI must override profile independent of order");
        require(a.tls.ca_file == (dir / "certs/ca.pem").string(), "credential path must be profile-relative");
        const auto b = parse({"turtle", "run", "--profile", path, "--samples", "9"}).run;
        require(a.profile_hash == b.profile_hash, "repetition count must not fragment profile identity");
        const auto c = parse({"turtle", "run", "--profile", path, "--tickets", "2"}).run;
        require(c.profile_hash != b.profile_hash, "TLS changes must affect profile identity");
        require(parse({"turtle", "--help"}).action == turtle::config::Command::Action::Help, "help action");
        require(parse({"turtle", "capabilities"}).action == turtle::config::Command::Action::Capabilities, "capabilities action");
        bool rejected = false;
        try { (void)parse({"turtle", "run", "--samples", "-1"}); } catch (const std::invalid_argument&) { rejected = true; }
        require(rejected, "negative sample count accepted");
        std::filesystem::remove_all(dir);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        std::filesystem::remove_all(dir);
        return 1;
    }
}
