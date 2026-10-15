#include "lifecycle/lifecycle.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include <unistd.h>
using nlohmann::json;
void require(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}
json sample(const std::filesystem::path& path) {
    std::ifstream in(path);
    std::string line;
    std::getline(in, line);
    return json::parse(line);
}
int main(int argc, char** argv) {
    if (argc != 2)
        return 1;
    const auto root =
        std::filesystem::temp_directory_path() / ("turtle-lifecycle-" + std::to_string(::getpid()));
    try {
        turtle::model::RunConfig config;
        config.client_adapter = config.server_adapter = "runtime_probe";
        config.adapter_directory = argv[1];
        config.output_directory = (root / "normal").string();
        config.samples = 2;
        config.warmups = 1;
        config.connections = 2;
        config.perf = false;
        config.pin_cores = false;
        config.client_cpu = 1;
        config.server_cpu = 2;
        config.calibration_samples = 2;
        config.tls.cipher = "TLS_AES_256_GCM_SHA384";
        bool rejected_cipher = false;
        try {
            (void)turtle::lifecycle::run(config);
        } catch (const std::invalid_argument&) {
            rejected_cipher = true;
        }
        require(rejected_cipher, "direct runtime accepted an out-of-scope cipher suite");
        config.tls.cipher = "TLS_AES_128_GCM_SHA256";
        require(turtle::lifecycle::run(config) == 0, "normal lifecycle failed");
        std::set<long> pids;
        for (const char* directory : {"sample-000001", "sample-000002"})
            for (const char* role : {"client", "server"}) {
                auto data = sample(root / "normal" / directory / (std::string(role) + ".jsonl"));
                require(data.at("valid").get<bool>(), "invalid sample");
                require(data.at("pinned_cpu") == -1,
                        "disabled affinity reported requested CPU as actual");
                pids.insert(data.at("pid").get<long>());
                require(data.at("connections").size() == 3, "scenario connection missing");
                require(data.at("connections")[0].at("warmup") == true &&
                            data.at("connections")[1].at("warmup") == false &&
                            data.at("connections")[2].at("warmup") == false,
                        "warmup and measured connections were mixed");
                require(data.at("declaration").at("is_mock").get<bool>(), "mock mislabeled");
                for (const auto& connection : data.at("connections"))
                    require(connection.at("application_verified").get<bool>(),
                            "application not verified");
            }
        require(pids.size() == 4, "role processes were reused");
        for (const char* directory : {"sample-000001", "sample-000002"}) {
            require(!std::filesystem::exists(root / "normal" / directory / "lookup.jsonl") &&
                        !std::filesystem::exists(root / "normal" / directory / "ca.jsonl"),
                    "lookup-disabled run emitted service artifacts");
        }
        config.output_directory = (root / "invalid").string();
        config.warmups = 0;
        ::setenv("TURTLE_MOCK_VERIFY_FAIL", "1", 1);
        const auto rc = turtle::lifecycle::run(config);
        ::unsetenv("TURTLE_MOCK_VERIFY_FAIL");
        require(rc != 0, "failed verification accepted");
        require(!std::filesystem::exists(root / "invalid" / "sample-000002"),
                "invalid sample silently retried");
        require(std::filesystem::exists(root / "invalid" / "sample-000001" / "director.txt"),
                "director failure missing");
        std::filesystem::remove_all(root);
    } catch (const std::exception& error) {
        std::cerr << error.what() << " (artifacts: " << root << ")\n";
        return 1;
    }
}
