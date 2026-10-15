#include "lifecycle/lifecycle.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
using nlohmann::json;

void require(bool value, const std::string& reason) {
    if (!value)
        throw std::runtime_error(reason);
}

json sample_header(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::string line;
    require(static_cast<bool>(std::getline(input, line)),
            "sample header is unavailable: " + path.string());
    return json::parse(line);
}

std::uint64_t read_context(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::array<std::uint8_t, 8> bytes{};
    input.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    require(input.gcount() == static_cast<std::streamsize>(bytes.size()),
            "saved context is not eight bytes: " + path.string());
    require(input.peek() == std::ifstream::traits_type::eof(),
            "saved context has trailing bytes: " + path.string());
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i)
        value |= static_cast<std::uint64_t>(bytes[i]) << (i * 8);
    return value;
}

void write_context(const std::filesystem::path& path, std::uint64_t value) {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<std::uint8_t>(value >> (i * 8));
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    require(static_cast<bool>(output), "could not write context fixture: " + path.string());
}

std::array<std::string, 2> check_run(const std::filesystem::path& output,
                                     std::size_t loaded_size, std::uint64_t client_value,
                                     std::uint64_t server_value, std::set<long>& pids) {
    const std::array<const char*, 2> roles{"client", "server"};
    std::array<std::string, 2> context_hashes;
    for (const char* sample : {"sample-000001", "sample-000002"}) {
        const auto directory = output / sample;
        for (std::size_t role_index = 0; role_index < roles.size(); ++role_index) {
            const auto* role = roles[role_index];
            const auto prefix = directory / role;
            const auto header = sample_header(prefix.string() + ".jsonl");
            require(header.at("valid").get<bool>(), "context sample is invalid");
            require(header.at("loaded_context_size") == loaded_size,
                    "loaded context size differs");
            require(header.at("saved_context_size") == 8, "saved context size differs");
            require(header.at("declaration").at("is_mock").get<bool>(),
                    "context test was not marked as mock");
            require(header.at("declaration").at("context_serialization").get<bool>(),
                    "mock did not declare context serialization");
            require(header.at("connections").size() == 1,
                    "context test used an unexpected connection count");
            require(header.at("connections").at(0).at("application_verified").get<bool>(),
                    "application exchange was not verified");
            require(pids.insert(header.at("pid").get<long>()).second,
                    "role process was reused between context samples");
            const auto loaded_hash = header.at("loaded_context_hash").get<std::string>();
            if (loaded_size == 0)
                require(loaded_hash.empty(), "cold sample recorded a context hash");
            else {
                require(!loaded_hash.empty(), "restored sample omitted its context hash");
                if (context_hashes[role_index].empty())
                    context_hashes[role_index] = loaded_hash;
                else
                    require(context_hashes[role_index] == loaded_hash,
                            "fixed context hash changed between samples");
            }
            const auto expected = std::string(role) == "client" ? client_value : server_value;
            require(read_context(prefix.string() + ".context.bin") == expected,
                    "saved context value differs");
        }
    }
    return context_hashes;
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2)
        return 2;
    const auto root =
        std::filesystem::temp_directory_path() / ("turtle-context-" + std::to_string(::getpid()));
    try {
        turtle::model::RunConfig config;
        config.client_adapter = config.server_adapter = "mock";
        config.adapter_directory = argv[1];
        config.samples = 2;
        config.warmups = 0;
        config.perf = false;
        config.pin_cores = false;
        config.calibration_samples = 2;

        std::set<long> pids;
        const auto cold = root / "cold";
        config.output_directory = cold.string();
        require(turtle::lifecycle::run(config) == 0, "cold context run failed");
        const auto cold_hashes = check_run(cold, 0, 1, 1, pids);
        require(cold_hashes[0].empty() && cold_hashes[1].empty(),
                "cold run retained an input context hash");

        const auto restored = root / "restored";
        config.context_directory = (cold / "sample-000001").string();
        config.output_directory = restored.string();
        require(turtle::lifecycle::run(config) == 0, "restored context run failed");
        const auto restored_hashes = check_run(restored, 8, 2, 2, pids);
        require(restored_hashes[0] == restored_hashes[1],
                "identical role contexts produced different hashes");

        const auto inputs = root / "inputs";
        std::filesystem::create_directories(inputs);
        write_context(inputs / "client.context.bin", 5);
        write_context(inputs / "server.context.bin", 9);
        const auto separate = root / "separate";
        config.context_directory = inputs.string();
        config.output_directory = separate.string();
        require(turtle::lifecycle::run(config) == 0, "role-specific context run failed");
        const auto separate_hashes = check_run(separate, 8, 6, 10, pids);
        require(separate_hashes[0] != separate_hashes[1],
                "different role contexts produced the same hash");

        std::filesystem::remove_all(root);
    } catch (const std::exception& error) {
        std::cerr << error.what() << " (artifacts: " << root << ")\n";
        return 1;
    }
}
