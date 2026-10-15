#include "lifecycle/lifecycle.hpp"
#include "model/run_config.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

extern "C" long __wrap_syscall(long number, ...) {
    // TURTLE invokes syscall(2) only for perf_event_open. Keeping the wrapper
    // local to this executable makes the lifecycle failure deterministic
    // without adding a production injection hook.
    errno = number == SYS_perf_event_open ? EACCES : ENOSYS;
    return -1;
}

namespace {
using Json = nlohmann::json;

void require(bool condition, const char* reason) {
    if (!condition)
        throw std::runtime_error(reason);
}

std::vector<Json> read_lines(const std::filesystem::path& path) {
    std::ifstream input(path);
    require(static_cast<bool>(input), "expected artifact is missing");
    std::vector<Json> rows;
    for (std::string line; std::getline(input, line);)
        if (!line.empty())
            rows.push_back(Json::parse(line));
    return rows;
}

void require_perf_failure(const Json& capabilities) {
    require(capabilities.at("perf_requested_scope") == "user+kernel",
            "requested perf scope was not recorded");
    require(capabilities.at("perf_status") == "unsupported" &&
                capabilities.at("perf_effective_scope").is_null(),
            "unsupported perf scope was presented as effective");
    require(capabilities.at("perf_failure_stage") == "cycles_open" &&
                capabilities.at("perf_error_number") == EACCES,
            "perf setup diagnostic was not preserved");
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2)
        return 2;
    const auto root = std::filesystem::temp_directory_path() /
                      ("turtle-perf-scope-failure-" + std::to_string(::getpid()));
    try {
        std::filesystem::create_directories(root);
        const auto object_path = root / "object.pem";
        std::ofstream(object_path) << "deterministic lookup object";

        turtle::model::RunConfig config;
        config.client_adapter = config.server_adapter = "mock";
        config.adapter_directory = argv[1];
        config.output_directory = (root / "run").string();
        config.samples = 1;
        config.connections = 1;
        config.perf = true;
        config.perf_scope = turtle::model::PerfScope::UserKernel;
        config.pin_cores = false;
        config.calibration_samples = 1;
        config.lookup.enabled = true;
        config.lookup.object_file = object_path.string();

        require(turtle::lifecycle::run(config) != 0,
                "unavailable kernel-inclusive perf request was accepted");
        const auto sample = root / "run" / "sample-000001";
        for (const char* role : {"client", "server"}) {
            const auto rows = read_lines(sample / (std::string(role) + ".jsonl"));
            require(!rows.empty() && rows.front().at("valid") == false,
                    "failed TLS role did not preserve partial raw");
            require(rows.front().at("invalid_reason").get<std::string>().find(
                        "requested perf scope user+kernel is unavailable") !=
                        std::string::npos,
                    "TLS raw omitted the strict perf refusal reason");
            require_perf_failure(rows.front().at("capabilities"));
        }

        const auto ca = read_lines(sample / "ca.jsonl");
        require(!ca.empty() && ca.front().at("record_kind") == "header",
                "CA header was not preserved");
        require_perf_failure(ca.front().at("capabilities"));
        require(ca.back().at("record_kind") == "footer" &&
                    ca.back().at("artifact_status") == "partial" &&
                    ca.back().at("incomplete_reason").get<std::string>().find(
                        "requested perf scope user+kernel is unavailable") !=
                        std::string::npos,
                "CA partial artifact omitted the strict perf refusal reason");

        const auto attempts = read_lines(root / "run" / "attempts.jsonl");
        bool final_found = false;
        for (const auto& row : attempts) {
            if (row.value("record_kind", "") != "attempt_final")
                continue;
            final_found = true;
            require(row.at("final_status") != "success",
                    "attempt ledger marked strict perf refusal successful");
            require(row.at("artifacts").at("client.jsonl") == "partial" &&
                        row.at("artifacts").at("server.jsonl") == "partial" &&
                        row.at("artifacts").at("ca.jsonl") == "partial",
                    "attempt ledger did not retain TLS and CA partial artifacts");
        }
        require(final_found, "attempt ledger omitted the failed attempt");
        std::filesystem::remove_all(root);
    } catch (const std::exception& error) {
        std::cerr << error.what() << " (artifacts: " << root << ")\n";
        return 1;
    }
}
