#include "config/config.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace turtle::config {
namespace {
Scenario scenario(const std::string& value) {
    for (auto item : {Scenario::Handshake, Scenario::ServerPing, Scenario::FinishedPing,
                      Scenario::ClientRequest})
        if (value == model::name(item))
            return item;
    throw std::invalid_argument(
        "scenario must be handshake, server-ping, finished-ping or client-request");
}
SendPolicy send_policy(const std::string& value) {
    if (value == "native")
        return SendPolicy::Native;
    if (value == "server-hello-first")
        return SendPolicy::ServerHelloFirst;
    throw std::invalid_argument("send policy must be native or server-hello-first");
}

using Json = nlohmann::json;
namespace fs = std::filesystem;

struct Option {
    std::string name;
    std::string value;
};

std::string resolve_path(const fs::path& path, const fs::path& base = fs::current_path()) {
    return (path.is_absolute() ? path : base / path).lexically_normal().string();
}

void pki(model::RunConfig& run, const fs::path& directory) {
    run.tls.ca_file = (directory / "ca.pem").string();
    run.tls.server_certificate = (directory / "server-chain.pem").string();
    run.tls.server_key = (directory / "server.key").string();
    run.tls.client_certificate = (directory / "client-chain.pem").string();
    run.tls.client_key = (directory / "client.key").string();
}

template <class T> T number(std::string_view value, std::string_view option) {
    T result{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
        throw std::invalid_argument(std::string(option) + ": expected a whole number");
    return result;
}

void validate_address(const std::string& address) {
    in_addr parsed{};
    if (::inet_pton(AF_INET, address.c_str(), &parsed) != 1)
        throw std::invalid_argument("IPv4 address must be numeric: " + address);
}

void endpoint_address(const std::string& value, std::string& address, std::uint16_t& port) {
    const auto separator = value.find(':');
    if (separator == std::string::npos)
        throw std::invalid_argument("endpoint must be IPv4:port");
    address = value.substr(0, separator);
    validate_address(address);
    port = number<std::uint16_t>(std::string_view(value).substr(separator + 1), "endpoint port");
}

model::Mode mode(const std::string& value) {
    if (value == "timing")
        return model::Mode::Timing;
    if (value == "memory")
        return model::Mode::Memory;
    if (value == "trace")
        return model::Mode::Trace;
    throw std::invalid_argument("mode must be timing, memory, or trace");
}

model::PerfScope perf_scope(const std::string& value) {
    if (value == "user")
        return model::PerfScope::User;
    if (value == "user+kernel")
        return model::PerfScope::UserKernel;
    throw std::invalid_argument("measurement.perf_scope must be user or user+kernel");
}

model::CacheMode cache_mode(const std::string& value) {
    if (value == "empty")
        return model::CacheMode::Empty;
    if (value == "fixed-snapshot")
        return model::CacheMode::FixedSnapshot;
    throw std::invalid_argument("lookup.cache_mode must be empty or fixed-snapshot");
}

void keys(const Json& object, std::initializer_list<std::string_view> allowed,
          const char* section) {
    if (!object.is_object())
        throw std::invalid_argument(std::string(section) + " must be an object");
    for (const auto& [key, value] : object.items()) {
        (void)value;
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end())
            throw std::invalid_argument(std::string(section) + ": unknown field " + key);
    }
}

template <class T> void assign(const Json& object, const char* key, T& value) {
    if (object.contains(key))
        value = object.at(key).get<T>();
}

void profile(model::RunConfig& run, const std::string& filename) {
    std::ifstream stream(filename);
    if (!stream)
        throw std::runtime_error("cannot read profile: " + filename);
    Json document;
    stream >> document;
    keys(document, {"type", "schema", "name", "endpoint", "scenario"}, "endpoint profile");
    if (document.at("type") != "turtle-endpoint-profile" || document.at("schema") != 1)
        throw std::invalid_argument("expected turtle-endpoint-profile schema 1");
    const auto shared = document.at("scenario");
    keys(shared, {"tls", "measurement"}, "shared scenario");
    auto resolved = document.at("endpoint");
    resolved["name"] = document.value("name", "default");
    for (const auto* section : {"tls", "measurement"}) {
        if (!resolved.contains(section))
            resolved[section] = Json::object();
        if (shared.contains(section))
            resolved[section].update(shared.at(section));
    }
    document = std::move(resolved);
    keys(document,
         {"name", "tls", "socket", "measurement", "lookup", "technique", "pki",
          "certificate_inputs"},
         "profile");
    assign(document, "name", run.profile_name);
    const auto base = fs::path(resolve_path(filename)).parent_path();
    if (document.contains("pki"))
        pki(run, resolve_path(document.at("pki").get<std::string>(), base));
    if (document.contains("tls")) {
        const auto& tls = document.at("tls");
        keys(tls,
             {"version",
              "cipher",
              "group",
              "signature",
              "server_name",
              "ca_file",
              "server_certificate",
              "server_key",
              "client_certificate",
              "client_key",
              "mutual_auth",
              "compatibility_ccs",
              "framework_io",
              "tickets",
              "application_bytes",
              "record_size_limit",
              "certificate_compression",
              "scenario",
              "send_policy",
              "client_application_bytes",
              "server_application_bytes"},
             "tls");
        if (tls.value("version", "TLS1.3") != "TLS1.3")
            throw std::invalid_argument("only certificate-based TLS1.3 is in scope");
        assign(tls, "cipher", run.tls.cipher);
        assign(tls, "group", run.tls.group);
        assign(tls, "signature", run.tls.signature);
        assign(tls, "server_name", run.tls.server_name);
        assign(tls, "mutual_auth", run.tls.mutual_auth);
        assign(tls, "compatibility_ccs", run.tls.compatibility_ccs);
        assign(tls, "framework_io", run.tls.framework_io);
        assign(tls, "tickets", run.tls.tickets);
        assign(tls, "application_bytes", run.tls.application_bytes);
        if (tls.contains("scenario"))
            run.tls.scenario = scenario(tls.at("scenario"));
        if (tls.contains("send_policy"))
            run.tls.send_policy = send_policy(tls.at("send_policy"));
        if (tls.contains("client_application_bytes"))
            run.tls.client_application_bytes =
                tls.at("client_application_bytes").get<std::size_t>();
        if (tls.contains("server_application_bytes"))
            run.tls.server_application_bytes =
                tls.at("server_application_bytes").get<std::size_t>();
        assign(tls, "record_size_limit", run.tls.record_size_limit);
        assign(tls, "certificate_compression", run.tls.certificate_compression);
        for (auto [key, value] : {std::pair{"ca_file", &run.tls.ca_file},
                                  {"server_certificate", &run.tls.server_certificate},
                                  {"server_key", &run.tls.server_key},
                                  {"client_certificate", &run.tls.client_certificate},
                                  {"client_key", &run.tls.client_key}})
            if (tls.contains(key))
                *value = resolve_path(tls.at(key).get<std::string>(), base);
    }
    if (document.contains("socket")) {
        const auto& socket = document.at("socket");
        keys(socket, {"tcp_nodelay", "send_buffer", "receive_buffer"}, "socket");
        assign(socket, "tcp_nodelay", run.tcp_nodelay);
        assign(socket, "send_buffer", run.socket_send_buffer);
        assign(socket, "receive_buffer", run.socket_receive_buffer);
    }
    if (document.contains("measurement")) {
        const auto& m = document.at("measurement");
        keys(m,
             {"connections",
              "warmups",
              "batch",
              "seed",
              "timeout_ms",
              "flush_grace_ms",
              "cpu",
              "event_capacity",
              "stream_capacity",
              "keylog_capacity",
              "calibration_samples",
              "mode",
              "perf",
              "perf_scope",
              "kernel_timestamps",
              "tx_timestamps",
              "cpu_profile",
              "channel_observer",
              "isolate",
              "pin_cores"},
             "measurement");
        assign(m, "cpu", run.cpu);
        assign(m, "connections", run.connections);
        assign(m, "warmups", run.warmups);
        assign(m, "batch", run.batch);
        assign(m, "seed", run.seed);
        assign(m, "timeout_ms", run.timeout_ms);
        assign(m, "flush_grace_ms", run.flush_grace_ms);
        assign(m, "event_capacity", run.event_capacity);
        assign(m, "stream_capacity", run.stream_capacity);
        assign(m, "keylog_capacity", run.keylog_capacity);
        assign(m, "calibration_samples", run.calibration_samples);
        assign(m, "perf", run.perf);
        if (m.contains("perf_scope"))
            run.perf_scope = perf_scope(m.at("perf_scope").get<std::string>());
        assign(m, "kernel_timestamps", run.kernel_timestamps);
        assign(m, "tx_timestamps", run.tx_timestamps);
        assign(m, "cpu_profile", run.cpu_profile);
        assign(m, "channel_observer", run.channel_observer);
        assign(m, "isolate", run.isolate);
        assign(m, "pin_cores", run.pin_cores);
        if (m.contains("mode"))
            run.mode = mode(m.at("mode").get<std::string>());
    }
    if (document.contains("lookup")) {
        const auto& lookup = document.at("lookup");
        keys(lookup,
             {"enabled", "object_file", "cache_mode", "snapshot_file", "address", "source_address",
              "port", "control_port"},
             "lookup");
        assign(lookup, "enabled", run.lookup.enabled);
        assign(lookup, "address", run.lookup.address);
        assign(lookup, "source_address", run.lookup.source_address);
        assign(lookup, "port", run.lookup.port);
        assign(lookup, "control_port", run.lookup.control_port);
        if (lookup.contains("object_file")) {
            const auto value = lookup.at("object_file").get<std::string>();
            if (value.empty())
                throw std::invalid_argument("lookup.object_file must not be empty");
            run.lookup.object_file = resolve_path(value, base);
        }
        if (lookup.contains("cache_mode"))
            run.lookup.cache_mode = cache_mode(lookup.at("cache_mode").get<std::string>());
        if (lookup.contains("snapshot_file") && !lookup.at("snapshot_file").is_null()) {
            const auto value = lookup.at("snapshot_file").get<std::string>();
            if (value.empty())
                throw std::invalid_argument("lookup.snapshot_file must not be empty");
            run.lookup.snapshot_file = resolve_path(value, base);
        }
    }
    run.profile_document = document.dump();
}

void validate(const model::RunConfig& run) {
    for (const auto* address : {&run.address, &run.control_address, &run.source_address})
        validate_address(*address);
    if (run.role == Role::Client && (run.address == "0.0.0.0" || run.control_address == "0.0.0.0"))
        throw std::invalid_argument("0.0.0.0 is a bind address; connect to a server IPv4 address");
    if (run.role == Role::Client && (run.port == 0 || run.control_port == 0))
        throw std::invalid_argument("client destination ports must be 1..65535");
    if (run.tls.scenario != Scenario::Handshake &&
        (run.tls.client_application_bytes.value_or(run.tls.application_bytes) == 0 ||
         run.tls.server_application_bytes.value_or(run.tls.application_bytes) == 0))
        throw std::invalid_argument("application scenario requires positive directional sizes");
    if (run.tls.scenario == Scenario::FinishedPing && !run.tls.framework_io)
        throw std::invalid_argument("finished-ping requires framework output buffering");
    if (run.tx_timestamps &&
        (run.mode != model::Mode::Trace || !run.tls.framework_io || !run.channel_observer))
        throw std::invalid_argument("tx_timestamps requires trace mode and observed framework I/O");
    if (run.tx_timestamps && run.stream_capacity >= 0xffffffffULL)
        throw std::invalid_argument(
            "TX timestamp byte mapping requires streams shorter than 2^32 bytes");
    if (run.cpu_profile && run.mode != model::Mode::Timing)
        throw std::invalid_argument("cpu_profile requires a separate timing-mode run");
    if (run.cpu_profile && run.lookup.enabled)
        throw std::invalid_argument("cpu_profile currently supports the TLS-only scenario");
    if (run.lookup.enabled && run.tls.scenario != Scenario::ClientRequest)
        throw std::invalid_argument("synthetic lookup currently requires client-request");
    if (run.connections == 0 || run.connections > 1025)
        throw std::invalid_argument("connections must be 1..1025");
    if (run.warmups > 1024)
        throw std::invalid_argument("warmups must be 0..1024");
    if (run.connections > 1025 - run.warmups)
        throw std::invalid_argument("warmups and connections together must not exceed 1025");
    if (run.timeout_ms == 0 || run.tls.application_bytes == 0 || run.event_capacity == 0 ||
        run.stream_capacity == 0 || run.keylog_capacity == 0 || run.socket_send_buffer <= 0 ||
        run.socket_receive_buffer <= 0)
        throw std::invalid_argument(
            "timeout, application length, and buffer capacities must be positive");
    if (run.flush_grace_ms == 0 || run.flush_grace_ms > 5000)
        throw std::invalid_argument("flush_grace_ms must be 1..5000");
    if (!run.perf && run.perf_scope == model::PerfScope::UserKernel)
        throw std::invalid_argument(
            "measurement.perf_scope user+kernel requires measurement.perf=true");
    if (run.lookup.enabled && run.lookup.object_file.empty())
        throw std::invalid_argument("lookup object_file could not be resolved");
    if (run.lookup.cache_mode == model::CacheMode::FixedSnapshot &&
        run.lookup.snapshot_file.empty())
        throw std::invalid_argument("fixed-snapshot lookup requires snapshot_file");
    if (run.lookup.cache_mode == model::CacheMode::Empty && !run.lookup.snapshot_file.empty())
        throw std::invalid_argument("empty lookup cache must not specify snapshot_file");
    if (run.tls.cipher != "TLS_AES_128_GCM_SHA256")
        throw std::invalid_argument("TURTLE supports only TLS_AES_128_GCM_SHA256");
    if (run.tls.group.empty() || run.tls.signature.empty())
        throw std::invalid_argument("group and signature must be explicit");
}

void identify(model::RunConfig& run) {
    Json effective =
        run.profile_document.empty() ? Json::object() : Json::parse(run.profile_document);
    effective["name"] = run.profile_name;
    effective.erase("pki");
    effective["tls"] = {{"version", "TLS1.3"},
                        {"cipher", run.tls.cipher},
                        {"group", run.tls.group},
                        {"signature", run.tls.signature},
                        {"server_name", run.tls.server_name},
                        {"ca_file", run.tls.ca_file},
                        {"server_certificate", run.tls.server_certificate},
                        {"server_key", run.tls.server_key},
                        {"client_certificate", run.tls.client_certificate},
                        {"client_key", run.tls.client_key},
                        {"mutual_auth", run.tls.mutual_auth},
                        {"compatibility_ccs", run.tls.compatibility_ccs},
                        {"framework_io", run.tls.framework_io},
                        {"tickets", run.tls.tickets},
                        {"application_bytes", run.tls.application_bytes},
                        {"scenario", model::name(run.tls.scenario)},
                        {"send_policy", model::name(run.tls.send_policy)},
                        {"client_application_bytes",
                         run.tls.client_application_bytes.value_or(run.tls.application_bytes)},
                        {"server_application_bytes",
                         run.tls.server_application_bytes.value_or(run.tls.application_bytes)},
                        {"record_size_limit", run.tls.record_size_limit},
                        {"certificate_compression", run.tls.certificate_compression}};
    effective["socket"] = {{"tcp_nodelay", run.tcp_nodelay},
                           {"send_buffer", run.socket_send_buffer},
                           {"receive_buffer", run.socket_receive_buffer}};
    effective["lookup"] = {{"enabled", run.lookup.enabled},
                           {"object_file", run.lookup.object_file},
                           {"cache_mode", model::name(run.lookup.cache_mode)},
                           {"snapshot_file", run.lookup.snapshot_file.empty()
                                                 ? Json(nullptr)
                                                 : Json(run.lookup.snapshot_file)}};
    // Retain certificate content identity as well as paths. Do not put private
    // key contents into JSON. These fingerprints are not cryptographic hashes.
    effective["certificate_inputs"] = Json::object();
    for (auto [name, path] : {std::pair{"ca", run.tls.ca_file},
                              {"server", run.tls.server_certificate},
                              {"client", run.tls.client_certificate}}) {
        std::ifstream file(path, std::ios::binary);
        if (file) {
            const std::string bytes{std::istreambuf_iterator<char>(file), {}};
            effective["certificate_inputs"][name] = {{"bytes", bytes.size()},
                                                     {"fingerprint", model::fingerprint(bytes)}};
        } else {
            effective["certificate_inputs"][name] = nullptr;
        }
    }
    // Repetition/output paths do not change the TLS profile. Execution settings
    // remain in each raw header's config rather than fragmenting profile groups.
    effective.erase("measurement");
    run.profile_document = effective.dump();
    run.profile_hash = model::fingerprint(run.profile_document);
}
} // namespace

Command parse(int argc, char** argv, Role role) {
    Command command;
    auto& run = command.run;
    run.role = role;
    pki(run, resolve_path("pki/default"));
    int first = 1;
    if (argc > 1 && std::string_view(argv[1]) == "capabilities") {
        command.action = Command::Action::Capabilities;
        ++first;
    }
    if (argc == 1)
        command.action = Command::Action::Help;
    std::vector<Option> options;
    for (int i = first; i < argc; ++i) {
        const std::string name = argv[i];
        if (name == "--help" || name == "-h") {
            command.action = Command::Action::Help;
            continue;
        }
        if (name == "--no-perf" || name == "--no-kernel-timestamps" || name == "--no-isolate" ||
            name == "--no-affinity" || name == "--mutual-auth" || name == "--server-auth" ||
            name == "--native-io" || name == "--no-ccs" || name == "--tx-timestamps" ||
            name == "--cpu-profile") {
            options.push_back({name, {}});
            continue;
        }
        if (++i == argc)
            throw std::invalid_argument("missing value for " + name);
        options.push_back({name, argv[i]});
    }
    // A profile is always applied before overrides, regardless of CLI order.
    bool profile_seen = false;
    for (const auto& option : options)
        if (option.name == "--profile") {
            if (profile_seen)
                throw std::invalid_argument("only one profile may be supplied");
            profile(run, option.value);
            profile_seen = true;
        }
    for (const auto& [name, value] : options) {
        if (name == "--profile")
            continue;
        if (name == "--module")
            run.adapter_path = resolve_path(value);
        else if (name == "--connect" || name == "--control-connect" || name == "--listen" ||
                 name == "--control-listen") {
            const bool listening = name == "--listen" || name == "--control-listen";
            if (listening != (role == Role::Server))
                throw std::invalid_argument(name + " is only valid for the " +
                                            (listening ? "server" : "client"));
            if (name == "--control-connect" || name == "--control-listen")
                endpoint_address(value, run.control_address, run.control_port);
            else
                endpoint_address(value, run.address, run.port);
        } else if (name == "--source-address")
            run.source_address = value;
        else if (name == "--run-id")
            run.run_id = value;
        else if (name == "--context-id")
            run.context_id = value;
        else if (name == "--sample")
            run.sample = number<std::uint64_t>(value, name);
        else if (name == "--clock-domain")
            run.clock_domain = value;
        else if (name == "--phase-fd")
            run.phase_fd = number<int>(value, name);
        else if (name == "--ready-file")
            run.ready_file = resolve_path(value);
        else if (name == "--ca")
            run.tls.ca_file = resolve_path(value);
        else if (name == "--certificate")
            (role == Role::Client ? run.tls.client_certificate : run.tls.server_certificate) =
                resolve_path(value);
        else if (name == "--key")
            (role == Role::Client ? run.tls.client_key : run.tls.server_key) = resolve_path(value);
        else if (name == "--network-evidence") {
            std::ifstream input(value);
            Json evidence;
            input >> evidence;
            run.network_handoff = model::NetworkHandoff{evidence.at("net_profile").dump(),
                                                        evidence.at("provenance_file"),
                                                        evidence.at("observations_file")};
        } else if (name == "--output")
            run.output_directory = resolve_path(value);
        else if (name == "--context")
            run.context_directory = resolve_path(value);
        else if (name == "--pki")
            pki(run, resolve_path(value));
        else if (name == "--mode")
            run.mode = mode(value);
        else if (name == "--connections")
            run.connections = number<std::size_t>(value, name);
        else if (name == "--warmups")
            run.warmups = number<std::size_t>(value, name);
        else if (name == "--batch")
            run.batch = number<std::uint64_t>(value, name);
        else if (name == "--seed")
            run.seed = number<std::uint64_t>(value, name);
        else if (name == "--timeout-ms")
            run.timeout_ms = number<unsigned>(value, name);
        else if (name == "--event-capacity")
            run.event_capacity = number<std::size_t>(value, name);
        else if (name == "--stream-capacity")
            run.stream_capacity = number<std::size_t>(value, name);
        else if (name == "--keylog-capacity")
            run.keylog_capacity = number<std::size_t>(value, name);
        else if (name == "--calibration-samples")
            run.calibration_samples = number<std::size_t>(value, name);
        else if (name == "--cpu")
            run.cpu = number<int>(value, name);
        else if (name == "--tickets")
            run.tls.tickets = number<std::uint32_t>(value, name);
        else if (name == "--application-bytes")
            run.tls.application_bytes = number<std::size_t>(value, name);
        else if (name == "--scenario")
            run.tls.scenario = scenario(value);
        else if (name == "--send-policy")
            run.tls.send_policy = send_policy(value);
        else if (name == "--client-bytes")
            run.tls.client_application_bytes = number<std::size_t>(value, name);
        else if (name == "--server-bytes")
            run.tls.server_application_bytes = number<std::size_t>(value, name);
        else if (name == "--cipher")
            run.tls.cipher = value;
        else if (name == "--group")
            run.tls.group = value;
        else if (name == "--signature")
            run.tls.signature = value;
        else if (name == "--no-perf")
            run.perf = false;
        else if (name == "--no-kernel-timestamps")
            run.kernel_timestamps = false;
        else if (name == "--tx-timestamps")
            run.tx_timestamps = true;
        else if (name == "--cpu-profile")
            run.cpu_profile = true;
        else if (name == "--no-isolate")
            run.isolate = false;
        else if (name == "--no-affinity")
            run.pin_cores = false;
        else if (name == "--mutual-auth")
            run.tls.mutual_auth = true;
        else if (name == "--server-auth")
            run.tls.mutual_auth = false;
        else if (name == "--native-io")
            run.tls.framework_io = false;
        else if (name == "--no-ccs")
            run.tls.compatibility_ccs = false;
        else
            throw std::invalid_argument("unknown option: " + name);
    }
    if (run.lookup.enabled && run.lookup.object_file.empty())
        run.lookup.object_file = run.tls.server_certificate;
    if (role == Role::Client) {
        run.tls.server_certificate.clear();
        run.tls.server_key.clear();
    } else {
        run.tls.client_certificate.clear();
        run.tls.client_key.clear();
    }
    if (run.cpu < -1 || run.context_id.empty() || run.run_id.size() > 128)
        throw std::invalid_argument("invalid endpoint CPU or execution identity");
    validate(run);
    identify(run);
    auto shared = Json::parse(run.profile_document).at("tls");
    for (const auto* field : {"ca_file", "server_certificate", "server_key", "client_certificate",
                              "client_key", "framework_io"})
        shared.erase(field);
    shared["connections"] = run.connections;
    shared["warmups"] = run.warmups;
    shared["seed"] = run.seed;
    shared["timeout_ms"] = run.timeout_ms;
    shared["flush_grace_ms"] = run.flush_grace_ms;
    run.scenario_document = shared.dump();
    run.profile_hash = model::fingerprint(run.scenario_document);
    return command;
}

std::string usage() {
    return "TURTLE independent endpoint\n"
           "Usage: turtle-client|turtle-server [OPTIONS] | capabilities\n"
           "  client: --connect IPv4:PORT --control-connect IPv4:PORT\n"
           "  server: --listen IPv4:PORT --control-listen IPv4:PORT\n"
           "  0.0.0.0 is a bind address, not a client destination\n"
           "  --module FILE (module build only)\n"
           "  --profile FILE --pki DIR | --ca FILE --certificate FILE --key FILE\n"
           "  --output DIR --context DIR --cpu N | --no-affinity\n"
           "  --run-id ID --context-id ID --sample N --batch N --seed N\n"
           "  --connections N --warmups N --timeout-ms N\n"
           "  --scenario handshake|server-ping|finished-ping|client-request\n"
           "  --send-policy native|server-hello-first --client-bytes N --server-bytes N\n"
           "  --mode timing|memory|trace --group NAME --signature NAME\n"
           "  --mutual-auth | --server-auth --no-perf --no-isolate\n"
           "  --tx-timestamps --cpu-profile --native-io --no-kernel-timestamps\n";
}
} // namespace turtle::config
