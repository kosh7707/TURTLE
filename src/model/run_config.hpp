#pragma once

// Runtime composition keeps service settings value-owned without pulling them
// into the core measurement model.
#include "model/model.hpp"
#include "model/service.hpp"

namespace turtle::model {

struct RunConfig {
    TlsConfig tls;
    std::string client_adapter = "openssl";
    std::string server_adapter = "openssl";
    std::string adapter_directory;
    std::string output_directory = "results/run";
    std::string profile_name = "default";
    std::string profile_hash;
    std::string profile_document;
    std::string context_directory;
    Mode mode = Mode::Timing;
    std::size_t samples = 1000;
    std::size_t warmups = 0;
    std::size_t connections = 1;
    std::uint64_t batch = 1;
    std::uint64_t seed = 1;
    unsigned timeout_ms = 10000;
    unsigned flush_grace_ms = 500;
    FailurePolicy failure_policy = FailurePolicy::FailFast;
    LookupConfig lookup;
    std::string network_manifest;
    std::optional<NetworkHandoff> network_handoff;
    std::size_t event_capacity = 32768;
    std::size_t stream_capacity = 1024 * 1024;
    std::size_t keylog_capacity = 256 * 1024;
    std::size_t calibration_samples = 64;
    bool tcp_nodelay = true;
    int socket_send_buffer = 65536;
    int socket_receive_buffer = 65536;
    bool kernel_timestamps = true;
    bool tx_timestamps = false; // separate, opt-in trace diagnostic
    bool cpu_profile = false;   // separate sampling run; perf.data proves collection
    bool channel_observer = true;
    bool perf = true;
    PerfScope perf_scope = PerfScope::User;
    bool isolate = true;
    bool pin_cores = true;
    int director_cpu = -1;
    int client_cpu = -1;
    int server_cpu = -1;
    int ca_cpu = -1;
};

} // namespace turtle::model
