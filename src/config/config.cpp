#include "config/config.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace turtle::config {
namespace {
using Json = nlohmann::json;
namespace fs = std::filesystem;

struct Option {
    std::string name;
    std::string value;
};

std::string resolve_path(const fs::path& path, const fs::path& base = fs::current_path()) {
    return (path.is_absolute() ? path : base / path).lexically_normal().string();
}

std::string adapter_directory() {
    std::error_code error;
    const auto executable = fs::read_symlink("/proc/self/exe", error);
    return resolve_path(error ? fs::path("build/adapters") : executable.parent_path() / "adapters");
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

model::Mode mode(const std::string& value) {
    if (value == "timing")
        return model::Mode::Timing;
    if (value == "memory")
        return model::Mode::Memory;
    if (value == "trace")
        return model::Mode::Trace;
    throw std::invalid_argument("mode must be timing, memory, or trace");
}

model::CacheMode cache_mode(const std::string& value) {
    if (value == "empty")
        return model::CacheMode::Empty;
    if (value == "fixed-snapshot")
        return model::CacheMode::FixedSnapshot;
    throw std::invalid_argument("lookup.cache_mode must be empty or fixed-snapshot");
}

model::FailurePolicy failure_policy(const std::string& value) {
    if (value == "fail-fast")
        return model::FailurePolicy::FailFast;
    if (value == "fixed-attempts")
        return model::FailurePolicy::FixedAttempts;
    throw std::invalid_argument(
        "measurement.failure_policy must be fail-fast or fixed-attempts");
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
             {"version", "cipher", "group", "signature", "server_name", "ca_file",
              "server_certificate", "server_key", "client_certificate", "client_key", "mutual_auth",
              "compatibility_ccs", "framework_io", "tickets", "application_bytes",
              "record_size_limit", "certificate_compression"},
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
             {"samples", "connections", "warmups", "batch", "seed", "timeout_ms",
              "failure_policy", "flush_grace_ms", "ca_cpu",
              "event_capacity", "stream_capacity", "keylog_capacity", "calibration_samples",
              "mode", "perf", "kernel_timestamps", "channel_observer", "isolate", "pin_cores", "director_cpu",
              "client_cpu", "server_cpu"},
             "measurement");
        assign(m, "samples", run.samples);
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
        assign(m, "kernel_timestamps", run.kernel_timestamps);
        assign(m, "channel_observer", run.channel_observer);
        assign(m, "isolate", run.isolate);
        assign(m, "pin_cores", run.pin_cores);
        assign(m, "director_cpu", run.director_cpu);
        assign(m, "client_cpu", run.client_cpu);
        assign(m, "server_cpu", run.server_cpu);
        assign(m, "ca_cpu", run.ca_cpu);
        if (m.contains("mode"))
            run.mode = mode(m.at("mode").get<std::string>());
        if (m.contains("failure_policy"))
            run.failure_policy = failure_policy(m.at("failure_policy").get<std::string>());
    }
    if (document.contains("lookup")) {
        const auto& lookup = document.at("lookup");
        keys(lookup, {"enabled", "object_file", "cache_mode", "snapshot_file"}, "lookup");
        assign(lookup, "enabled", run.lookup.enabled);
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

bool below(const fs::path& file, const fs::path& directory) {
    if (!file.is_absolute())
        return false;
    const auto relative = file.lexically_normal().lexically_relative(directory.lexically_normal());
    return !relative.empty() && *relative.begin() != "..";
}

void network_manifest(model::RunConfig& run) {
    std::ifstream stream(run.network_manifest);
    if (!stream)
        throw std::invalid_argument("cannot read network manifest: " + run.network_manifest);
    Json document;
    try {
        stream >> document;
        keys(document,
             {"type", "schema", "namespace_fds", "addresses", "interfaces", "net_profile",
              "provenance_file", "observations_file", "phase_control_fd"},
             "network manifest");
        if (document.at("type").get<std::string>() != "turtle-network-manifest" ||
            document.at("schema").get<unsigned>() != 1)
            throw std::invalid_argument("unsupported network manifest type or schema");

        model::NetworkHandoff handoff;
        const auto& fds = document.at("namespace_fds");
        keys(fds, {"client", "server", "ca"}, "network manifest namespace_fds");
        handoff.client_namespace_fd = fds.at("client").get<int>();
        handoff.server_namespace_fd = fds.at("server").get<int>();
        if (fds.contains("ca"))
            handoff.ca_namespace_fd = fds.at("ca").get<int>();
        else if (run.lookup.enabled)
            throw std::invalid_argument(
                "lookup-enabled network manifest requires the CA namespace fd");
        handoff.phase_control_fd = document.at("phase_control_fd").get<int>();
        if (handoff.client_namespace_fd < 0 || handoff.server_namespace_fd < 0 ||
            handoff.phase_control_fd < 0 ||
            (fds.contains("ca") && handoff.ca_namespace_fd < 0))
            throw std::invalid_argument("network manifest file descriptors must be non-negative");
        std::vector<int> inherited_fds = {handoff.client_namespace_fd,
                                          handoff.server_namespace_fd,
                                          handoff.phase_control_fd};
        if (fds.contains("ca"))
            inherited_fds.push_back(handoff.ca_namespace_fd);
        std::sort(inherited_fds.begin(), inherited_fds.end());
        if (std::adjacent_find(inherited_fds.begin(), inherited_fds.end()) !=
            inherited_fds.end())
            throw std::invalid_argument("network manifest file descriptors must be distinct");

        const auto& addresses = document.at("addresses");
        keys(addresses, {"client_tls", "server", "client_ca", "ca"},
             "network manifest addresses");
        handoff.client_tls_address = addresses.at("client_tls").get<std::string>();
        handoff.server_address = addresses.at("server").get<std::string>();
        if (addresses.contains("client_ca"))
            handoff.client_ca_address = addresses.at("client_ca").get<std::string>();
        if (addresses.contains("ca"))
            handoff.ca_address = addresses.at("ca").get<std::string>();
        if (run.lookup.enabled &&
            (!addresses.contains("client_ca") || !addresses.contains("ca")))
            throw std::invalid_argument(
                "lookup-enabled network manifest requires the CA addresses");
        if (handoff.client_tls_address != "10.203.1.2" ||
            handoff.server_address != "10.203.2.2" ||
            (addresses.contains("client_ca") &&
             handoff.client_ca_address != "10.203.3.2") ||
            (addresses.contains("ca") && handoff.ca_address != "10.203.4.2"))
            throw std::invalid_argument(
                "network manifest addresses do not match the fixed topology");

        const auto& interfaces = document.at("interfaces");
        keys(interfaces,
             {"client_tls", "server", "client_ca", "ca", "router_client_tls",
              "router_server", "router_client_ca", "router_ca"},
             "network manifest interfaces");
        handoff.client_tls_interface = interfaces.at("client_tls").get<std::string>();
        handoff.server_interface = interfaces.at("server").get<std::string>();
        if (interfaces.contains("client_ca"))
            handoff.client_ca_interface = interfaces.at("client_ca").get<std::string>();
        if (interfaces.contains("ca"))
            handoff.ca_interface = interfaces.at("ca").get<std::string>();
        handoff.router_client_tls_interface =
            interfaces.at("router_client_tls").get<std::string>();
        handoff.router_server_interface = interfaces.at("router_server").get<std::string>();
        if (interfaces.contains("router_client_ca"))
            handoff.router_client_ca_interface =
                interfaces.at("router_client_ca").get<std::string>();
        if (interfaces.contains("router_ca"))
            handoff.router_ca_interface = interfaces.at("router_ca").get<std::string>();
        if (run.lookup.enabled &&
            (!interfaces.contains("client_ca") || !interfaces.contains("ca") ||
             !interfaces.contains("router_client_ca") || !interfaces.contains("router_ca")))
            throw std::invalid_argument(
                "lookup-enabled network manifest requires the CA interfaces");
        if (handoff.client_tls_interface != "ctls" || handoff.server_interface != "stls" ||
            handoff.router_client_tls_interface != "rctls" ||
            handoff.router_server_interface != "rstls" ||
            (interfaces.contains("client_ca") && handoff.client_ca_interface != "cca") ||
            (interfaces.contains("ca") && handoff.ca_interface != "ca0") ||
            (interfaces.contains("router_client_ca") &&
             handoff.router_client_ca_interface != "rcca") ||
            (interfaces.contains("router_ca") && handoff.router_ca_interface != "rca0"))
            throw std::invalid_argument(
                "network manifest interfaces do not match the fixed topology");

        const auto& net_profile = document.at("net_profile");
        if (!net_profile.is_object())
            throw std::invalid_argument("network manifest net_profile must be an object");
        handoff.net_profile_document = net_profile.dump();
        handoff.provenance_file = document.at("provenance_file").get<std::string>();
        handoff.observations_file = document.at("observations_file").get<std::string>();
        const fs::path output = resolve_path(run.output_directory);
        if (!below(handoff.provenance_file, output) || !below(handoff.observations_file, output))
            throw std::invalid_argument(
                "network manifest provenance and observations files must be absolute paths "
                "under output");
        if (fs::path(handoff.provenance_file).lexically_normal() ==
            fs::path(handoff.observations_file).lexically_normal())
            throw std::invalid_argument(
                "network manifest provenance and observations files must be distinct");
        run.network_handoff = std::move(handoff);
    } catch (const std::invalid_argument&) {
        throw;
    } catch (const std::exception& error) {
        throw std::invalid_argument(std::string("invalid network manifest: ") + error.what());
    }
}

void validate(const model::RunConfig& run) {
    if (run.samples == 0 || run.samples > 10000000)
        throw std::invalid_argument("samples must be 1..10000000");
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
    if (run.ca_cpu < -1)
        throw std::invalid_argument("ca_cpu must be -1 or a non-negative CPU index");
    if (run.lookup.enabled && run.lookup.object_file.empty())
        throw std::invalid_argument("lookup object_file could not be resolved");
    if (run.lookup.cache_mode == model::CacheMode::FixedSnapshot &&
        run.lookup.snapshot_file.empty())
        throw std::invalid_argument("fixed-snapshot lookup requires snapshot_file");
    if (run.lookup.cache_mode == model::CacheMode::Empty && !run.lookup.snapshot_file.empty())
        throw std::invalid_argument("empty lookup cache must not specify snapshot_file");
    for (const auto& name : {run.client_adapter, run.server_adapter})
        if (name.empty() ||
            name.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") !=
                std::string::npos)
            throw std::invalid_argument(
                "adapter name must be a module basename (use --adapter-dir for its directory)");
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
                        {"record_size_limit", run.tls.record_size_limit},
                        {"certificate_compression", run.tls.certificate_compression}};
    effective["socket"] = {{"tcp_nodelay", run.tcp_nodelay},
                           {"send_buffer", run.socket_send_buffer},
                           {"receive_buffer", run.socket_receive_buffer}};
    effective["lookup"] = {
        {"enabled", run.lookup.enabled},
        {"object_file", run.lookup.object_file},
        {"cache_mode", model::name(run.lookup.cache_mode)},
        {"snapshot_file",
         run.lookup.snapshot_file.empty() ? Json(nullptr) : Json(run.lookup.snapshot_file)}};
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

Command parse(int argc, char** argv) {
    Command command;
    auto& run = command.run;
    run.adapter_directory = adapter_directory();
    pki(run, resolve_path("pki/default"));
    int first = 1;
    if (argc > 1 && std::string_view(argv[1]) == "run")
        ++first;
    else if (argc > 1 && std::string_view(argv[1]) == "capabilities") {
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
            name == "--native-io" || name == "--no-ccs") {
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
        if (name == "--client")
            run.client_adapter = value;
        else if (name == "--server")
            run.server_adapter = value;
        else if (name == "--adapter-dir")
            run.adapter_directory = resolve_path(value);
        else if (name == "--output")
            run.output_directory = resolve_path(value);
        else if (name == "--context")
            run.context_directory = resolve_path(value);
        else if (name == "--network-manifest") {
            if (!run.network_manifest.empty())
                throw std::invalid_argument("only one network manifest may be supplied");
            run.network_manifest = resolve_path(value);
        }
        else if (name == "--pki")
            pki(run, resolve_path(value));
        else if (name == "--mode")
            run.mode = mode(value);
        else if (name == "--samples")
            run.samples = number<std::size_t>(value, name);
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
        else if (name == "--director-cpu")
            run.director_cpu = number<int>(value, name);
        else if (name == "--client-cpu")
            run.client_cpu = number<int>(value, name);
        else if (name == "--server-cpu")
            run.server_cpu = number<int>(value, name);
        else if (name == "--tickets")
            run.tls.tickets = number<std::uint32_t>(value, name);
        else if (name == "--application-bytes")
            run.tls.application_bytes = number<std::size_t>(value, name);
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
    if (run.lookup.object_file.empty())
        run.lookup.object_file = run.tls.server_certificate;
    if (!run.network_manifest.empty())
        network_manifest(run);
    validate(run);
    identify(run);
    return command;
}

std::string usage() {
    return "TURTLE: normal-path TLS 1.3 full-handshake benchmark\n"
           "Usage: turtle run [OPTIONS] | turtle capabilities | turtle --help\n"
           "  --client NAME --server NAME  Adapter modules (default: openssl)\n"
           "  --adapter-dir DIR            Modules directory (default: beside executable)\n"
           "  --profile FILE --pki DIR     JSON profile; explicit test credentials\n"
           "  --samples N                  Fresh role processes per measured sample\n"
           "  --connections N              Measured connections in each role process\n"
           "  --warmups N                  Warm-up connections before measured connections\n"
           "  --mode timing|memory|trace   Separate instrumentation modes\n"
           "  --output DIR --context DIR   Raw output and optional saved setup context\n"
           "  --network-manifest FILE     Inherited namespace/phase-control handoff\n"
           "  --batch N --seed N --timeout-ms N\n"
           "  --mutual-auth | --server-auth; --tickets N; --no-ccs\n"
           "  --cipher NAME --group NAME --signature NAME --application-bytes N\n"
           "  Cipher suite is fixed to TLS_AES_128_GCM_SHA256.\n"
           "  --director-cpu N --client-cpu N --server-cpu N\n"
           "  --event-capacity N --stream-capacity N --keylog-capacity N\n"
           "  --calibration-samples N\n"
           "  --no-perf --no-kernel-timestamps --no-affinity --no-isolate\n"
           "  --native-io                 Compatibility only: no I/O-boundary capture\n"
           "CLI overrides profile settings. Existing sample files are never overwritten.\n";
}
} // namespace turtle::config
