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
std::vector<json> events(const std::filesystem::path& path) {
    std::ifstream in(path);
    std::string line;
    std::getline(in, line);
    std::vector<json> result;
    while (std::getline(in, line))
        if (!line.empty())
            result.push_back(json::parse(line));
    return result;
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
        config.perf_scope = turtle::model::PerfScope::UserKernel;
        bool rejected_disabled_kernel_scope = false;
        try {
            (void)turtle::lifecycle::run(config);
        } catch (const std::invalid_argument&) {
            rejected_disabled_kernel_scope = true;
        }
        require(rejected_disabled_kernel_scope,
                "direct runtime accepted disabled perf with user+kernel scope");
        require(!std::filesystem::exists(root / "normal"),
                "contradictory direct perf request created run artifacts");
        config.perf_scope = turtle::model::PerfScope::User;
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
                require(data.at("availability").at("tls_stream").at("available") == true,
                        "callback stream availability missing");
                require(data.at("availability").at("io_events").at("available") == true,
                        "callback I/O availability missing");
                for (const auto& connection : data.at("connections"))
                    require(connection.at("application_verified").get<bool>() &&
                                connection.at("primary_window").at("available").get<bool>() &&
                                !connection.at("start_sequence").is_null(),
                            "application or primary boundary not verified");
            }
        require(pids.size() == 4, "role processes were reused");
        for (const char* directory : {"sample-000001", "sample-000002"}) {
            require(!std::filesystem::exists(root / "normal" / directory / "lookup.jsonl") &&
                        !std::filesystem::exists(root / "normal" / directory / "ca.jsonl"),
                    "lookup-disabled run emitted service artifacts");
        }
        config.output_directory = (root / "observer-off").string();
        config.samples = 1;
        config.warmups = 0;
        config.connections = 1;
        config.channel_observer = false;
        require(turtle::lifecycle::run(config) == 0,
                "observer-disabled lifecycle failed");
        for (const char* role : {"client", "server"}) {
            const auto path = root / "observer-off" / "sample-000001" /
                              (std::string(role) + ".jsonl");
            const auto data = sample(path);
            require(data.at("valid").get<bool>() &&
                        data.at("config").at("channel_observer") == false,
                    "observer-disabled run or raw config invalid");
            require(data.at("observation_level") == "observer-disabled" &&
                        data.at("declaration").at("callback_io").get<bool>(),
                    "callback I/O was mislabeled when observer was disabled");
            require(data.at("capabilities").at("kernel_timestamp_configured").get<bool>() &&
                        data.at("connections")[0].at("socket").at("kernel_timestamps").get<bool>(),
                    "timestamp configuration facts changed with observer toggle");
            for (const auto* field : {"tls_stream", "io_events", "kernel_receive_events"})
                require(data.at("availability").at(field).at("available") == false &&
                            data.at("availability").at(field).at("reason") ==
                                "channel_observer_disabled",
                        "observer-disabled availability reason changed");
            const auto& connection = data.at("connections")[0];
            require(connection.at("application_verified").get<bool>(),
                    "observer-disabled application exchange failed");
            if (std::string(role) == "client")
                require(connection.at("primary_window").at("available").get<bool>() &&
                            !connection.at("start_sequence").is_null(),
                        "client call boundary disappeared when observer was disabled");
            else
                require(!connection.at("primary_window").at("available").get<bool>() &&
                            connection.at("start_sequence").is_null() &&
                            connection.at("primary_window").at("reason") ==
                                "server_first_receive_not_observed",
                        "server primary window used a fallback boundary");
            bool call = false, wait = false, io = false, kernel = false;
            for (const auto& event : events(path)) {
                const auto kind = event.at("kind").get<std::string>();
                call = call || kind == "CALL_BEGIN" || kind == "CALL_END";
                wait = wait || kind == "WAIT_BEGIN" || kind == "WAIT_END";
                io = io || kind.rfind("IO_", 0) == 0;
                kernel = kernel || kind == "KERNEL_RX";
            }
            require(call && wait && !io && !kernel,
                    "CALL/WAIT retention or observer event suppression changed");
            const auto prefix = path.parent_path() / role;
            require(std::filesystem::file_size(prefix.string() + ".conn-0.sent.bin") == 0 &&
                        std::filesystem::file_size(prefix.string() + ".conn-0.received.bin") == 0,
                    "observer-disabled stream bytes were presented as observed");
        }
        config.output_directory = (root / "invalid").string();
        config.channel_observer = true;
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
