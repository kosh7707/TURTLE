#include "lifecycle/lifecycle.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
using nlohmann::json;
void require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
std::vector<json> read_lines(const std::filesystem::path& path) {
    std::ifstream input(path); std::vector<json> result; std::string line;
    while (std::getline(input, line)) if (!line.empty()) result.push_back(json::parse(line));
    return result;
}
turtle::model::RunConfig base(const char* adapters, const std::filesystem::path& output) {
    turtle::model::RunConfig config;
    config.client_adapter = config.server_adapter = "mock";
    config.adapter_directory = adapters; config.output_directory = output.string();
    config.samples = 3; config.perf = false; config.pin_cores = false;
    config.calibration_samples = 2; return config;
}
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const auto root = std::filesystem::temp_directory_path() /
                      ("turtle-attempt-" + std::to_string(::getpid()));
    try {
        ::setenv("TURTLE_MOCK_VERIFY_FAIL", "1", 1);
        auto fail_fast = base(argv[1], root / "fail-fast");
        require(turtle::lifecycle::run(fail_fast) != 0, "fail-fast failure accepted");
        auto rows = read_lines(root / "fail-fast" / "attempts.jsonl");
        std::size_t started = 0, not_attempted = 0;
        for (const auto& row : rows) {
            if (row.value("record_kind", "") == "attempt_started") ++started;
            if (row.value("record_kind", "") == "run_summary")
                not_attempted = row.at("not_attempted").get<std::size_t>();
        }
        require(started == 1 && not_attempted == 2, "fail-fast ledger denominator differs");
        require(!std::filesystem::exists(root / "fail-fast" / "sample-000002"),
                "fail-fast started a later attempt");

        auto fixed = base(argv[1], root / "fixed");
        fixed.failure_policy = turtle::model::FailurePolicy::FixedAttempts;
        require(turtle::lifecycle::run(fixed) != 0, "fixed-attempt failures accepted");
        rows = read_lines(root / "fixed" / "attempts.jsonl");
        started = 0; std::size_t errors = 0;
        for (const auto& row : rows) {
            if (row.value("record_kind", "") == "attempt_started") ++started;
            if (row.value("record_kind", "") == "attempt_final" &&
                row.value("final_status", "") == "error") ++errors;
        }
        require(started == 3 && errors == 3, "fixed attempts did not preserve every failure");
        for (int i = 1; i <= 3; ++i) {
            char sample[32]; std::snprintf(sample, sizeof sample, "sample-%06d", i);
            require(std::filesystem::exists(root / "fixed" / sample / "director.txt"),
                    "fixed attempt artifact missing");
        }
        ::unsetenv("TURTLE_MOCK_VERIFY_FAIL");
        std::filesystem::remove_all(root);
    } catch (const std::exception& error) {
        ::unsetenv("TURTLE_MOCK_VERIFY_FAIL");
        std::cerr << error.what() << " (artifacts: " << root << ")\n"; return 1;
    }
}
