#pragma once
#include <turtle/implementation.h>
#include <cstdint>
#include <string>
#include <vector>
namespace turtle::run {
struct Options {
    turtle_role role = TURTLE_CLIENT;
    std::string host = "127.0.0.1", output, run_id = "standalone";
    std::uint16_t port = 4433;
    std::size_t chunk = 0, app_chunk = 0;
    std::string scenario = "S3", auth = "server", measured_role = "client", recording = "basic", purpose = "measurement";
    std::string request = "ping", greeting = "helo", response = "pong";
    bool check = false;
    unsigned timeout = 15;
    bool controlled = false;
    bool perf_counters = false, cpu_samples = false;
    std::vector<const char*> arguments;
};
int run(const turtle_implementation&, const Options&);
}
