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
         {"name", "tls", "socket", "measurement", "technique", "pki", "certificate_inputs"},
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
             {"samples", "warmups", "batch", "seed", "timeout_ms", "event_capacity",
              "stream_capacity", "keylog_capacity", "calibration_samples", "mode", "perf",
              "kernel_timestamps", "isolate", "pin_cores", "director_cpu", "client_cpu",
              "server_cpu"},
             "measurement");
        assign(m, "samples", run.samples);
        assign(m, "warmups", run.warmups);
        assign(m, "batch", run.batch);
        assign(m, "seed", run.seed);
        assign(m, "timeout_ms", run.timeout_ms);
        assign(m, "event_capacity", run.event_capacity);
        assign(m, "stream_capacity", run.stream_capacity);
        assign(m, "keylog_capacity", run.keylog_capacity);
        assign(m, "calibration_samples", run.calibration_samples);
        assign(m, "perf", run.perf);
        assign(m, "kernel_timestamps", run.kernel_timestamps);
        assign(m, "isolate", run.isolate);
        assign(m, "pin_cores", run.pin_cores);
        assign(m, "director_cpu", run.director_cpu);
        assign(m, "client_cpu", run.client_cpu);
        assign(m, "server_cpu", run.server_cpu);
        if (m.contains("mode"))
            run.mode = mode(m.at("mode").get<std::string>());
    }
    run.profile_document = document.dump();
}

void validate(const model::RunConfig& run) {
    if (run.samples == 0 || run.samples > 10000000 || run.warmups > 1024)
        throw std::invalid_argument("samples must be 1..10000000; warmups must be 0..1024");
    if (run.timeout_ms == 0 || run.tls.application_bytes == 0 || run.event_capacity == 0 ||
        run.stream_capacity == 0 || run.keylog_capacity == 0 || run.socket_send_buffer <= 0 ||
        run.socket_receive_buffer <= 0)
        throw std::invalid_argument(
            "timeout, application length, and buffer capacities must be positive");
    for (const auto& name : {run.client_adapter, run.server_adapter})
        if (name.empty() ||
            name.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") !=
                std::string::npos)
            throw std::invalid_argument(
                "adapter name must be a module basename (use --adapter-dir for its directory)");
    if (run.tls.cipher.empty() || run.tls.group.empty() || run.tls.signature.empty())
        throw std::invalid_argument("cipher, group, and signature must be explicit");
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
        else if (name == "--pki")
            pki(run, resolve_path(value));
        else if (name == "--mode")
            run.mode = mode(value);
        else if (name == "--samples")
            run.samples = number<std::size_t>(value, name);
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
           "  --samples N --warmups N      Fresh role processes per measured sample\n"
           "  --mode timing|memory|trace   Separate instrumentation modes\n"
           "  --output DIR --context DIR   Raw output and optional saved setup context\n"
           "  --batch N --seed N --timeout-ms N\n"
           "  --mutual-auth | --server-auth; --tickets N; --no-ccs\n"
           "  --cipher NAME --group NAME --signature NAME --application-bytes N\n"
           "  --director-cpu N --client-cpu N --server-cpu N\n"
           "  --event-capacity N --stream-capacity N --keylog-capacity N\n"
           "  --calibration-samples N\n"
           "  --no-perf --no-kernel-timestamps --no-affinity --no-isolate\n"
           "  --native-io                 Compatibility only: no I/O-boundary capture\n"
           "CLI overrides profile settings. Existing sample files are never overwritten.\n";
}
} // namespace turtle::config
