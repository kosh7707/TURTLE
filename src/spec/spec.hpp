#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <turtle/implementation.h>
namespace turtle {
enum class Scenario { Handshake, ServerPing, FinishedPing, ClientRequest };
struct Spec {
    std::string contract = "turtle-message-run/1";
    std::string run_id, context_id, pki = "pki/default", output, address = "127.0.0.1";
    std::string lookup_address = "127.0.0.1", lookup_digest, lookup_snapshot;
    std::uint16_t lookup_port = 44332;
    std::size_t lookup_size = 4096;
    std::string network_condition = "local-unshaped";
    std::string group = "P-256";
    std::uint16_t port = 44330, control_port = 44331;
    Scenario scenario = Scenario::ClientRequest;
    turtle_role role = TURTLE_CLIENT;
    bool mutual = false, white = false, bundle = false, hello_first = false;
    bool allocations = false, cpu_samples = false, kernel = false;
    bool cpu = true, perf = false, stream = false, external = false;
    std::size_t client_bytes = 32, server_bytes = 32, record_size = 16384;
    std::size_t max_message = 1024 * 1024, event_capacity = 100000, io_chunk = 0;
    unsigned connections = 1, warmups = 0, timeout_ms = 30000;
    std::uint64_t seed = 1;
};
Spec read_spec(const std::string&, turtle_role);
const char* scenario_name(Scenario);
} // namespace turtle
