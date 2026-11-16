#include "spec.hpp"
#include <fstream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <set>
namespace turtle {
using json = nlohmann::json;
const char* scenario_name(Scenario s) {
    switch (s) {
    case Scenario::Handshake:
        return "handshake";
    case Scenario::ServerPing:
        return "server-ping";
    case Scenario::FinishedPing:
        return "finished-ping";
    case Scenario::ClientRequest:
        return "client-request";
    }
    return "invalid";
}
Spec read_spec(const std::string& path, turtle_role role) {
    std::ifstream file(path);
    json j;
    file >> j;
    if (j.at("contract") != "turtle-message-run/1")
        throw std::runtime_error("unsupported run contract");
    static const std::set<std::string> fields = {
        "contract",      "run_id",         "output",        "pki",
        "address",       "port",           "control_port",  "lookup_address",
        "lookup_port",   "lookup_size",    "lookup_sha256", "lookup_snapshot",
        "group",         "mutual_auth",    "scenario",      "depth",
        "records",       "send",           "thread_cpu",    "perf_counters",
        "allocations",   "cpu_samples",    "kernel",        "stream",
        "external_peer", "connections",    "warmups",       "timeout_ms",
        "seed",          "client_bytes",   "server_bytes",  "record_size",
        "max_message",   "event_capacity", "io_chunk",      "network_condition"};
    for (auto it = j.begin(); it != j.end(); ++it)
        if (!fields.count(it.key()))
            throw std::runtime_error("unknown run field: " + it.key());
    for (const char* key : {"port", "control_port", "lookup_port", "lookup_size", "connections",
                            "warmups", "timeout_ms", "seed", "client_bytes", "server_bytes",
                            "record_size", "max_message", "event_capacity", "io_chunk"})
        if (j.contains(key) && !j[key].is_number_unsigned())
            throw std::runtime_error(std::string("unsigned integer required: ") + key);
    for (const char* key : {"port", "control_port", "lookup_port"})
        if (j.contains(key) &&
            (j[key].get<std::uint64_t>() == 0 || j[key].get<std::uint64_t>() > 65535))
            throw std::runtime_error("port outside uint16 range");
    for (const char* key : {"connections", "warmups", "timeout_ms"})
        if (j.contains(key) && j[key].get<std::uint64_t>() > 1000000)
            throw std::runtime_error("run count or timeout capacity exceeded");
    Spec s;
    s.role = role;
    s.run_id = j.at("run_id");
    if (s.run_id.empty() || s.run_id.size() > 256)
        throw std::runtime_error("run_id must contain 1..256 bytes");
    s.context_id = s.run_id + (role == TURTLE_CLIENT ? "/client" : "/server");
    s.output = j.at("output");
    s.pki = j.value("pki", s.pki);
    s.address = j.value("address", s.address);
    s.port = j.value("port", s.port);
    s.control_port = j.value("control_port", s.control_port);
    s.lookup_digest = j.value("lookup_sha256", std::string{});
    s.lookup_snapshot = j.value("lookup_snapshot", std::string{});
    s.lookup_address = j.value("lookup_address", s.lookup_address);
    s.lookup_port = j.value("lookup_port", s.lookup_port);
    s.lookup_size = j.value("lookup_size", s.lookup_size);
    s.network_condition = j.value("network_condition", s.network_condition);
    s.group = j.value("group", s.group);
    s.mutual = j.value("mutual_auth", false);
    auto scenario = j.value("scenario", std::string("client-request"));
    if (scenario == "handshake")
        s.scenario = Scenario::Handshake;
    else if (scenario == "server-ping")
        s.scenario = Scenario::ServerPing;
    else if (scenario == "finished-ping")
        s.scenario = Scenario::FinishedPing;
    else if (scenario != "client-request")
        throw std::runtime_error("unknown scenario");
    auto depth = j.value("depth", std::string("black-box"));
    if (depth != "black-box" && depth != "white-box")
        throw std::runtime_error("unknown measurement depth");
    s.white = depth == "white-box";
    auto records = j.value("records", std::string("preserve"));
    if (records != "preserve" && records != "bundle")
        throw std::runtime_error("unknown record policy");
    s.bundle = records == "bundle";
    auto send = j.value("send", std::string("flight"));
    if (send != "flight" && send != "server-hello-first")
        throw std::runtime_error("unknown send policy");
    s.hello_first = send == "server-hello-first";
    s.allocations = j.value("allocations", false);
    s.cpu_samples = j.value("cpu_samples", false);
    s.kernel = j.value("kernel", false);
    s.cpu = j.value("thread_cpu", true);
    s.perf = j.value("perf_counters", false);
    s.stream = j.value("stream", false);
    s.external = j.value("external_peer", false);
    s.connections = j.value("connections", 1u);
    s.warmups = j.value("warmups", 0u);
    s.timeout_ms = j.value("timeout_ms", 30000u);
    s.seed = j.value("seed", std::uint64_t(1));
    s.client_bytes = j.value("client_bytes", s.client_bytes);
    s.server_bytes = j.value("server_bytes", s.server_bytes);
    s.record_size = j.value("record_size", s.record_size);
    s.max_message = j.value("max_message", s.max_message);
    s.event_capacity = j.value("event_capacity", s.event_capacity);
    s.io_chunk = j.value("io_chunk", s.io_chunk);
    if (!s.connections || !s.record_size || s.record_size > 16384 || s.max_message < 16384 ||
        s.lookup_size > 16 * 1024 * 1024 || s.max_message > 16 * 1024 * 1024 ||
        s.client_bytes == 0 || s.server_bytes == 0 || s.client_bytes > s.max_message ||
        s.server_bytes > s.max_message || s.event_capacity < 32)
        throw std::runtime_error("invalid run capacity");
    return s;
}
} // namespace turtle
