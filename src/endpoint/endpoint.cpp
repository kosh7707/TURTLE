#include <turtle/endpoint.h>
#include "run/runner.hpp"
#include <charconv>
#include <iostream>
#include <stdexcept>
#include <string_view>
namespace {
std::size_t number(std::string_view value) {
    std::size_t n = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), n);
    if (error != std::errc{} || end != value.data() + value.size()) throw std::runtime_error("invalid_number");
    return n;
}
}
turtle::run::Options turtle::run::options(int argc, char** argv) {
    turtle::run::Options o;
    bool role = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view key(argv[i]);
        if (key == "--") {
            while (++i < argc) o.arguments.push_back(argv[i]);
            break;
        }
        if (key == "--check") { o.check = true; continue; }
        if (key == "--controlled") { o.controlled = true; continue; }
        if (key == "--perf-counters") { o.perf_counters = true; continue; }
        if (key == "--cpu-samples") { o.cpu_samples = true; continue; }
        if (++i >= argc) throw std::runtime_error("missing_option_value");
        const std::string_view value(argv[i]);
        if (key == "--role") {
            if (value != "client" && value != "server") throw std::runtime_error("invalid_role");
            o.role = value == "client" ? TURTLE_CLIENT : TURTLE_SERVER;
            role = true;
        } else if (key == "--host") o.host = value;
        else if (key == "--scenario" && value.size() == 2 && value[0] == 'S' && value[1] >= '0' && value[1] <= '4') o.scenario = value;
        else if (key == "--auth" && (value == "server" || value == "mtls")) o.auth = value;
        else if (key == "--measured-role" && (value == "client" || value == "server")) o.measured_role = value;
        else if (key == "--recording" && (value == "off" || value == "basic" || value == "detailed")) o.recording = value;
        else if (key == "--purpose" && (value == "warmup" || value == "measurement" || value == "capability" || value == "profile")) o.purpose = value;
        else if (key == "--app-chunk") o.app_chunk = number(value);
        else if (key == "--request") o.request = value;
        else if (key == "--response") o.response = value;
        else if (key == "--greeting") o.greeting = value;
        else if (key == "--output") o.output = value;
        else if (key == "--run-id") o.run_id = value;
        else if (key == "--io-chunk") o.chunk = number(value);
        else if (key == "--port") {
            const auto n = number(value);
            if (n > 65535) throw std::runtime_error("invalid_port");
            o.port = static_cast<std::uint16_t>(n);
        } else if (key == "--timeout") {
            const auto n = number(value);
            if (!n || n > 3600) throw std::runtime_error("invalid_timeout");
            o.timeout = static_cast<unsigned>(n);
        } else throw std::runtime_error("unknown_option");
    }
    for (const auto* payload : {&o.request, &o.greeting, &o.response})
        if (payload->empty() || payload->size() > 16384) throw std::runtime_error("invalid_payload_length");
    if (!o.check && !o.controlled) throw std::runtime_error("controlled_execution_required");
    if (!role || (!o.check && o.output.empty())) throw std::runtime_error("role_and_output_required");
    return o;
}
