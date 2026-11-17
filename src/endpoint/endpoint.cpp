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
turtle::run::Options options(int argc, char** argv) {
    turtle::run::Options o;
    bool role = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view key(argv[i]);
        if (key == "--") {
            while (++i < argc) o.arguments.push_back(argv[i]);
            break;
        }
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
    if (!o.controlled) throw std::runtime_error("controlled_execution_required");
    if (!role || o.output.empty()) throw std::runtime_error("role_and_output_required");
    return o;
}
}
extern "C" int turtle_endpoint_main(const turtle_implementation* api, int argc, char** argv) {
    try {
        if (!api || !api->name || !api->prepare || !api->release || !api->handshake || !api->read || !api->write)
            throw std::runtime_error("incomplete_function_table");
        return turtle::run::run(*api, options(argc, argv));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\nusage: " << argv[0]
                  << " --role client|server --output DIR [--host IPv4 --port N --controlled] -- IMPLEMENTATION_ARGS\n";
        return 1;
    }
}
