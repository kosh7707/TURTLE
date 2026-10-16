#include "lifecycle/lifecycle.hpp"
#include "model/run_config.hpp"
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
        ::unsetenv("TURTLE_MOCK_VERIFY_FAIL");
        auto normal = base(argv[1], root / "normal");
        normal.samples = 2;
        normal.warmups = 1;
        normal.connections = 2;
        require(turtle::lifecycle::run(normal) == 0, "normal attempts failed");
        auto rows = read_lines(root / "normal" / "attempts.jsonl");
        require(rows.size() == 6, "normal ledger row count differs");
        for (std::size_t i = 0; i < normal.samples; ++i) {
            const auto& started_row = rows[1 + i * 2];
            const auto& final_row = rows[2 + i * 2];
            require(started_row.at("record_kind") == "attempt_started" &&
                        final_row.at("record_kind") == "attempt_final",
                    "normal ledger row order differs");
            require(started_row.at("attempt_id") == i + 1 &&
                        final_row.at("attempt_id") == i + 1,
                    "normal attempt index differs");
            require(started_row.at("participants") ==
                        json::array({"tls-server", "tls-client"}) &&
                        final_row.at("participants") == started_row.at("participants"),
                    "normal participant order differs");
            require(started_row.at("connections") == json::array({0, 1, 2}) &&
                        final_row.at("connections") == started_row.at("connections"),
                    "normal connection indices differ");
            require(started_row.at("artifacts") ==
                        json({{"server.jsonl", "missing"}, {"client.jsonl", "missing"}}),
                    "normal started artifacts differ");
            require(final_row.at("artifacts") ==
                        json({{"server.jsonl", "complete"}, {"client.jsonl", "complete"}}),
                    "normal final artifacts differ");
            require(started_row.at("measurement_deadline_monotonic_ns").get<std::uint64_t>() > 0 &&
                        final_row.at("measurement_deadline_monotonic_ns") ==
                            started_row.at("measurement_deadline_monotonic_ns"),
                    "normal attempt deadline differs");
            require(final_row.at("final_status") == "success" &&
                        final_row.at("failure_phase") == "none" &&
                        final_row.at("reason") == "",
                    "normal final status differs");
        }
        const auto& normal_summary = rows.back();
        require(normal_summary.at("record_kind") == "run_summary" &&
                    normal_summary.at("requested") == 2 && normal_summary.at("started") == 2 &&
                    normal_summary.at("success") == 2 && normal_summary.at("timeout") == 0 &&
                    normal_summary.at("error") == 0 && normal_summary.at("incomplete") == 0 &&
                    normal_summary.at("not_attempted") == 0 &&
                    normal_summary.at("missing_artifacts") == 0,
                "normal ledger denominator differs");

        ::setenv("TURTLE_MOCK_VERIFY_FAIL", "1", 1);
        auto fail_fast = base(argv[1], root / "fail-fast");
        require(turtle::lifecycle::run(fail_fast) != 0, "fail-fast failure accepted");
        rows = read_lines(root / "fail-fast" / "attempts.jsonl");
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
