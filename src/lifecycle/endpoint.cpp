#include "capability/capability.hpp"
#include "lifecycle/lifecycle.hpp"
#include "lifecycle/lookup_runtime.hpp"
#include "lifecycle/peer_session.hpp"
#include "lifecycle/role_runtime.hpp"
#include "model/sample.hpp"
#include "record/record.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unistd.h>

namespace turtle::lifecycle {
namespace {
std::string read_id(const char* path) {
    std::ifstream file(path);
    std::string value;
    std::getline(file, value);
    if (value.empty())
        throw std::runtime_error("execution identity unavailable");
    return value;
}
} // namespace
int run_endpoint(model::RunConfig config, AdapterEntry builtin) {
    namespace fs = std::filesystem;
    fs::create_directories(config.output_directory);
    const auto raw =
        fs::path(config.output_directory) / (std::string(model::name(config.role)) + ".jsonl");
    if (fs::exists(raw))
        throw std::runtime_error("endpoint output already exists");
    if (config.clock_domain.empty())
        config.clock_domain = "linux-boot:" + read_id("/proc/sys/kernel/random/boot_id");
    if (config.role == Role::Client && config.run_id.empty())
        config.run_id = read_id("/proc/sys/kernel/random/uuid");
    if (builtin)
        config.adapter_path = fs::read_symlink("/proc/self/exe").string();
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(config.timeout_ms);
    detail::PeerSession session(config, deadline);
    bool runtime_started = false;
    try {
        capability::choose_cpus(config, capability::inspect_environment());
        session.connect();
        const auto saved = detail::load_serialized_context(config, config.role);
        const auto lookup = config.role == Role::Client ? detail::load_lookup_inputs(config)
                                                        : detail::LookupInputs{};
        const auto address =
            tcp::prepare_dial(config.source_address, {config.address, config.port});
        runtime_started = true;
        return detail::run_tls_role(config, config.role, config.sample, config.output_directory,
                                    session, address, deadline, builtin, saved,
                                    config.role == Role::Client ? lookup.reference.get() : nullptr,
                                    config.role == Role::Client ? lookup.initial.get() : nullptr);
    } catch (const std::exception& error) {
        if (!runtime_started || !fs::exists(raw)) {
            model::SampleInfo info;
            info.config = config;
            info.role = config.role;
            info.sample = config.sample;
            info.batch = config.batch;
            info.pid = ::getpid();
            info.valid = false;
            info.preparation = session.status();
            info.failure_phase = info.preparation.stage;
            info.invalid_reason = error.what();
            info.environment = capability::inspect_environment();
            record::Buffer empty({1, 1, 1, config.warmups + config.connections});
            record::Writer writer(config.output_directory, config.role,
                                  config.warmups + config.connections);
            writer.write(info, empty);
        }
        std::cerr << model::name(config.role) << ": " << error.what() << '\n';
        return 1;
    }
}
} // namespace turtle::lifecycle
