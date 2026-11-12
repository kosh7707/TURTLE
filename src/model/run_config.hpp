#pragma once

// Runtime composition keeps service settings value-owned without pulling them
// into the core measurement model.
#include "model/model.hpp"
#include "model/service.hpp"

namespace turtle::model {

struct RunConfig {
    std::uint64_t sample = 1;
    std::size_t warmups = 0;
    std::size_t connections = 1;
    std::uint64_t batch = 1;
    std::uint64_t seed = 1;
    std::size_t event_capacity = 32768;
    std::size_t stream_capacity = 1024 * 1024;
    std::size_t keylog_capacity = 256 * 1024;
    std::size_t calibration_samples = 64;
    std::string adapter_path;
    std::string adapter_linkage = "builtin";
    std::string implementation;
    std::string tls_linkage;
    std::string address = "127.0.0.1";
    std::string source_address = "0.0.0.0";
    std::string control_address = "127.0.0.1";
    std::string run_id;
    std::string context_id = "1";
    std::string clock_domain;
    std::string scenario_document;
    std::string ready_file; // optional local runner notification; never sent to peer
    std::string output_directory = "results/run";
    std::string profile_name = "default";
    std::string profile_hash;
    std::string profile_document;
    std::string context_directory;
    std::optional<NetworkHandoff> network_handoff;
    LookupConfig lookup;
    TlsConfig tls;
    Role role = Role::Client;
    int cpu = -1;
    int phase_fd = -1; // optional local observer, not a peer requirement
    Mode mode = Mode::Timing;
    unsigned timeout_ms = 10000;
    unsigned flush_grace_ms = 500;
    int socket_send_buffer = 65536;
    int socket_receive_buffer = 65536;
    PerfScope perf_scope = PerfScope::User;
    std::uint16_t port = 44330;
    std::uint16_t control_port = 44331;
    bool tcp_nodelay = true;
    bool kernel_timestamps = true;
    bool tx_timestamps = false; // separate, opt-in trace diagnostic
    bool cpu_profile = false;   // separate sampling run; perf.data proves collection
    bool channel_observer = true;
    bool perf = true;
    bool isolate = true;
    bool pin_cores = true;
};

} // namespace turtle::model
