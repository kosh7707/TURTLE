#include "capability/capability.hpp"
#include "lifecycle/lifecycle.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sched.h>
#include <stdexcept>
#include <unistd.h>

namespace {
enum class Failure { Endpoint, Director };
Failure failure = Failure::Endpoint;
pid_t director = 0;
void require(bool value, const char* reason) {
    if (!value)
        throw std::runtime_error(reason);
}
} // namespace

extern "C" int __real_sched_setaffinity(pid_t, std::size_t, const cpu_set_t*);
extern "C" int __wrap_sched_setaffinity(pid_t pid, std::size_t size, const cpu_set_t* mask) {
    const bool is_director = ::getpid() == director;
    if (CPU_COUNT(mask) == 1 && ((failure == Failure::Endpoint && !is_director) ||
                                 (failure == Failure::Director && is_director))) {
        errno = EPERM;
        return -1;
    }
    return __real_sched_setaffinity(pid, size, mask);
}

int main(int argc, char** argv) {
    if (argc != 2)
        return 2;
    const auto environment = turtle::capability::inspect_environment();
    if (environment.physical_cpus.size() < 3)
        return 77;
    director = ::getpid();
    const auto root =
        std::filesystem::temp_directory_path() / ("turtle-affinity-" + std::to_string(director));
    try {
        turtle::model::RunConfig config;
        config.client_adapter = config.server_adapter = "mock";
        config.adapter_directory = argv[1];
        config.samples = 1;
        config.perf = false;
        config.calibration_samples = 2;
        for (auto scenario : {Failure::Endpoint, Failure::Director}) {
            failure = scenario;
            config.output_directory =
                (root / (scenario == Failure::Endpoint ? "endpoint" : "director")).string();
            require(turtle::lifecycle::run(config) != 0, "CPU pin failure accepted as valid");
            const auto sample = std::filesystem::path(config.output_directory) / "sample-000001";
            std::ifstream status(sample / "director.txt");
            std::string line;
            std::getline(status, line);
            require(line.starts_with("invalid:"), "director did not record invalid sample");
            if (scenario == Failure::Endpoint) {
                unsigned headers = 0;
                for (const auto* role : {"client", "server"}) {
                    std::ifstream record(sample / (std::string(role) + ".jsonl"));
                    if (!std::getline(record, line) || line.empty())
                        continue;
                    const auto header = nlohmann::json::parse(line);
                    require(!header.at("valid").get<bool>(), "unfixed endpoint retained as valid");
                    require(header.at("pinned_cpu") == -1, "requested CPU recorded as actual CPU");
                    ++headers;
                }
                require(headers > 0, "no invalid endpoint header was retained");
            }
        }
        std::filesystem::remove_all(root);
    } catch (const std::exception& error) {
        std::cerr << error.what() << " (artifacts: " << root << ")\n";
        return 1;
    }
}
