#pragma once

// One endpoint sample owns its resolved runtime configuration by value.
#include "model/run_config.hpp"
#include "model/preparation.hpp"

namespace turtle::model {

struct SampleInfo {
    std::uint64_t sample = 0;
    std::uint64_t batch = 1;
    Role role = Role::Client;
    std::int64_t pid = 0;
    RunConfig config;
    PreparationInfo preparation;
    Declaration declaration;
    Environment environment;
    Capabilities capabilities;
    Calibration calibration;
    ClockPair clock_start;
    ClockPair clock_end;
    std::vector<ConnectionInfo> connections;
    bool valid = true;
    bool tls_stream_available = true;
    bool io_events_available = true;
    bool kernel_receive_events_available = false;
    std::string invalid_reason;
    std::string failure_phase;
    std::string observation_level = "L0";
    std::string tls_stream_reason;
    std::string io_events_reason;
    std::string kernel_receive_events_reason = "kernel_timestamps_not_configured";
    std::vector<std::string> incomplete;
    std::size_t saved_context_size = 0;
    std::size_t loaded_context_size = 0;
    std::string loaded_context_hash;
    int pinned_cpu = -1;
    bool perf_complete = false;
};

} // namespace turtle::model
