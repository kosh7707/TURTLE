#include "config/config.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <unistd.h>

using namespace turtle;
config::Command parse(std::initializer_list<std::string> options, Role role = Role::Client) {
    std::vector<std::string> args(options);
    std::vector<char*> argv;
    for (auto& value : args)
        argv.push_back(value.data());
    return config::parse(static_cast<int>(argv.size()), argv.data(), role);
}
int main() {
    const auto path = std::filesystem::temp_directory_path() /
                      ("endpoint-config-" + std::to_string(getpid()) + ".json");
    std::ofstream(path)
        << R"({"type":"turtle-endpoint-profile","schema":1,"scenario":{"tls":{"scenario":"server-ping"},"measurement":{"connections":3}},"endpoint":{"measurement":{"cpu":0,"perf":false}}})";
    const auto client = parse({"turtle-client", "--profile", path.string(), "--connections", "2",
                               "--pki", "/client/pki"})
                            .run;
    const auto server = parse({"turtle-server", "--profile", path.string(), "--connections", "2",
                               "--pki", "/server/pki"},
                              Role::Server)
                            .run;
    assert(client.connections == 2 && client.warmups == 0);
    assert(client.tls.server_key.empty() && client.tls.server_certificate.empty());
    assert(server.tls.client_key.empty() && server.tls.client_certificate.empty());
    assert(client.tls.ca_file == "/client/pki/ca.pem");
    assert(client.scenario_document == server.scenario_document);
    assert(client.profile_hash == server.profile_hash);
    assert(client.scenario_document.find("ca_file") == std::string::npos);
    const auto defaults = parse({"turtle-client", "--no-affinity"}).run;
    assert(defaults.connections == 1 && defaults.warmups == 0);
    assert(defaults.perf_scope == model::PerfScope::User && !defaults.pin_cores);
    assert(parse({"turtle-client", "--mode", "trace", "--tx-timestamps"}).run.tx_timestamps);
    const auto target = parse({"turtle-client", "--connect", "127.0.0.1:44430", "--control-connect",
                               "127.0.0.2:44431"})
                            .run;
    assert(target.address == "127.0.0.1" && target.port == 44430);
    assert(target.control_address == "127.0.0.2" && target.control_port == 44431);
    const auto bind =
        parse({"turtle-server", "--listen", "0.0.0.0:0", "--control-listen", "0.0.0.0:0"},
              Role::Server)
            .run;
    assert(bind.address == "0.0.0.0" && bind.port == 0 && bind.control_port == 0);
    for (const auto& options :
         {std::initializer_list<std::string>{"turtle-client", "--connect", "0.0.0.0:44330"},
          {"turtle-client", "--control-connect", "0.0.0.0:44331"},
          {"turtle-client", "--connect", "127.0.0.1:0"},
          {"turtle-client", "--connect", "127.0.0.1"},
          {"turtle-client", "--listen", "127.0.0.1:44330"}}) {
        bool rejected = false;
        try {
            (void)parse(options);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        assert(rejected);
    }
    std::filesystem::remove(path);
}
