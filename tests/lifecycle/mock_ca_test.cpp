#include "lifecycle/lifecycle.hpp"
#include "model/run_config.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
using nlohmann::json;
void require(bool value, const char* reason) {
    if (!value) throw std::runtime_error(reason);
}
std::string hex(std::string_view bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (unsigned char byte : bytes) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}
std::vector<json> lines(const std::filesystem::path& path) {
    std::ifstream input(path);
    require(static_cast<bool>(input), "artifact missing");
    std::vector<json> values;
    std::string line;
    while (std::getline(input, line)) if (!line.empty()) values.push_back(json::parse(line));
    return values;
}
void run_case(turtle::model::RunConfig config, const std::filesystem::path& output,
              bool expected_hit) {
    config.output_directory = output.string();
    require(turtle::lifecycle::run(config) == 0, "lookup lifecycle failed");
    auto lookup = lines(output / "sample-000001" / "lookup.jsonl");
    auto ca = lines(output / "sample-000001" / "ca.jsonl");
    require(!lookup.empty() && !ca.empty(), "service record empty");
    std::size_t lookup_summaries = 0, ca_summaries = 0;
    std::uint64_t lookup_sequence = 0, ca_sequence = 0;
    std::array<std::size_t, 2> lookup_ends{}, ca_ends{};
    for (const auto& value : lookup)
        if (value.value("record_kind", "") == "event") {
            const auto connection = value.at("connection").get<std::size_t>();
            require(connection < 2, "lookup event connection differs");
            require(value.at("sequence").get<std::uint64_t>() == ++lookup_sequence,
                    "lookup sequence did not continue across connections");
            require(value.at("stream_id") == "lookup-" + std::to_string(connection),
                    "lookup event stream identity was not stable until flush");
            if (value.at("kind") == "SCENARIO_END") ++lookup_ends[connection];
        } else if (value.value("record_kind", "") == "connection_summary") {
            const auto connection = value.at("connection").get<std::size_t>();
            ++lookup_summaries;
            require(connection < 2 && value.at("warmup") == (connection == 0),
                    "lookup warmup identity differs");
            require(value.at("stream_id") == "lookup-" + std::to_string(connection),
                    "lookup summary stream identity differs");
            require(value.at("cache_hit") == expected_hit, "lookup cache state differs");
            require(value.at("request_count") == (expected_hit ? 0 : 1), "lookup request count differs");
            require(value.at("artifact_status") == "complete", "lookup artifact incomplete");
        }
    for (const auto& value : ca)
        if (value.value("record_kind", "") == "event") {
            const auto connection = value.at("connection").get<std::size_t>();
            require(connection < 2, "CA event connection differs");
            require(value.at("sequence").get<std::uint64_t>() == ++ca_sequence,
                    "CA sequence did not continue across connections");
            require(value.at("stream_id") == "ca-" + std::to_string(connection),
                    "CA event stream identity was not stable until flush");
            if (value.at("kind") == "SCENARIO_END") ++ca_ends[connection];
        } else if (value.value("record_kind", "") == "connection_summary") {
            const auto connection = value.at("connection").get<std::size_t>();
            ++ca_summaries;
            require(connection < 2 && value.at("warmup") == (connection == 0),
                    "CA warmup identity differs");
            require(value.at("stream_id") == "ca-" + std::to_string(connection),
                    "CA summary stream identity differs");
            require(value.at("request_count") == (expected_hit ? 0 : 1), "CA request count differs");
        }
    require(lookup_summaries == 2 && ca_summaries == 2, "warmup/measurement service rows missing");
    require(lookup_ends == std::array<std::size_t, 2>{1, 1} &&
                ca_ends == std::array<std::size_t, 2>{1, 1},
            "service scenario did not end exactly once per connection");
    auto attempts = lines(output / "attempts.jsonl");
    bool success = false;
    for (const auto& value : attempts)
        success |= value.value("record_kind", "") == "attempt_final" &&
                   value.value("final_status", "") == "success";
    require(success, "successful attempt absent from ledger");
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const auto root = std::filesystem::temp_directory_path() /
                      ("turtle-mock-ca-" + std::to_string(::getpid()));
    try {
        std::filesystem::create_directories(root);
        const std::string object = "-----BEGIN CERTIFICATE-----\nTURTLE\n-----END CERTIFICATE-----\n";
        const auto object_path = root / "object.pem";
        std::ofstream(object_path, std::ios::binary).write(object.data(), object.size());
        turtle::model::RunConfig config;
        config.client_adapter = config.server_adapter = "mock";
        config.adapter_directory = argv[1];
        config.samples = 1; config.warmups = 1; config.connections = 1;
        config.perf = false; config.pin_cores = false; config.calibration_samples = 2;
        config.lookup.enabled = true; config.lookup.object_file = object_path.string();
        run_case(config, root / "cold", false);

        const auto snapshot_path = root / "snapshot.json";
        std::ofstream snapshot(snapshot_path);
        snapshot << "{\"type\":\"turtle-lookup-cache\",\"schema\":1,"
                    "\"object_id\":\"" << turtle::model::fingerprint(
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(object.data()), object.size()))
                 << "\",\"object_size\":" << object.size() << ",\"object_hex\":\"" << hex(object) << "\"}\n";
        snapshot.close();
        config.lookup.cache_mode = turtle::model::CacheMode::FixedSnapshot;
        config.lookup.snapshot_file = snapshot_path.string();
        run_case(config, root / "warm", true);
        std::filesystem::remove_all(root);
    } catch (const std::exception& error) {
        std::cerr << error.what() << " (artifacts: " << root << ")\n";
        return 1;
    }
}
