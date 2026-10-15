#include "report/report.hpp"
#include "report/network_evidence.hpp"

#include <algorithm>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace turtle::report {
namespace {
using Json = nlohmann::json;

struct Artifact {
    Json header = Json::object();
    Json footer = Json::object();
    std::vector<Json> events;
    std::map<std::size_t, Json> connections;
    std::filesystem::path path;
    bool present = false;
};

struct Attempt {
    std::uint64_t id = 0;
    bool started = false;
    std::string status = "not_attempted";
    std::string failure_phase = "none";
    std::string reason;
    Json connections = Json::array();
    Json observation_ids = Json::array();
    Json artifacts = Json::object();
    Json legacy_artifact_status = Json::array();
    std::string source = "attempt_ledger";
};

bool service_row(const Json& row, std::string_view type) {
    return row.is_object() && row.value("type", "") == type && row.value("schema", 0) == 1;
}

std::vector<Json> json_lines(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input)
        return {};
    std::vector<Json> rows;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty())
            continue;
        try {
            rows.push_back(Json::parse(line));
        } catch (const Json::exception&) {
            // A killed child may leave a partial final line. Earlier complete rows remain useful.
            break;
        }
    }
    return rows;
}

Artifact read_artifact(const std::filesystem::path& path, std::string_view type) {
    Artifact result;
    result.path = path;
    for (const auto& row : json_lines(path)) {
        if (!service_row(row, type))
            continue;
        result.present = true;
        const auto kind = row.value("record_kind", "");
        if (kind == "header")
            result.header = row;
        else if (kind == "event")
            result.events.push_back(row);
        else if (kind == "connection_summary" && row.contains("connection"))
            result.connections[row.at("connection").get<std::size_t>()] = row;
        else if (kind == "footer")
            result.footer = row;
    }
    return result;
}

std::optional<std::uint64_t> timestamp(const std::vector<Json>& events, std::size_t connection,
                                       std::string_view kind, bool last = false) {
    std::optional<std::uint64_t> value;
    for (const auto& event : events) {
        if (event.value("connection", std::size_t(-1)) != connection ||
            event.value("kind", "") != kind || !event.contains("monotonic_ns"))
            continue;
        const auto current = event.at("monotonic_ns").get<std::uint64_t>();
        if (!value || last)
            value = current;
        if (!last)
            break;
    }
    return value;
}

std::optional<std::uint64_t> cpu_timestamp(const std::vector<Json>& events,
                                           std::size_t connection, std::string_view kind,
                                           bool last = false) {
    std::optional<std::uint64_t> value;
    for (const auto& event : events) {
        if (event.value("connection", std::size_t(-1)) != connection ||
            event.value("kind", "") != kind || !event.contains("thread_cpu_ns") ||
            event.at("thread_cpu_ns").is_null())
            continue;
        const auto current = event.at("thread_cpu_ns").get<std::uint64_t>();
        if (!value || last)
            value = current;
        if (!last)
            break;
    }
    return value;
}

void duration(Json& row, std::string_view name, std::optional<std::uint64_t> begin,
              std::optional<std::uint64_t> end, std::string_view absent_reason) {
    const auto value_key = std::string(name) + "_ns";
    const auto reason_key = std::string(name) + "_reason";
    if (!begin || !end) {
        row[value_key] = nullptr;
        row[reason_key] = absent_reason;
    } else if (*end < *begin) {
        row[value_key] = nullptr;
        row[reason_key] = "boundary_order_invalid";
    } else {
        row[value_key] = *end - *begin;
        row[reason_key] = nullptr;
    }
}

Json interval_sum(const std::vector<Json>& events, std::size_t connection,
                  std::string_view begin_kind, std::string_view end_kind) {
    std::optional<std::uint64_t> begin;
    std::uint64_t total = 0;
    bool found = false;
    for (const auto& event : events) {
        if (event.value("connection", std::size_t(-1)) != connection ||
            !event.contains("monotonic_ns"))
            continue;
        const auto event_kind = event.value("kind", "");
        const auto now = event.at("monotonic_ns").get<std::uint64_t>();
        if (event_kind == begin_kind) {
            if (begin)
                return nullptr;
            begin = now;
        } else if (event_kind == end_kind) {
            if (!begin || now < *begin)
                return nullptr;
            total += now - *begin;
            begin.reset();
            found = true;
        }
    }
    return found && !begin ? Json(total) : Json(nullptr);
}

Json io_interval_sum(const std::vector<Json>& events, std::size_t connection) {
    std::optional<std::uint64_t> begin;
    std::string expected_end;
    std::uint64_t total = 0;
    bool found = false;
    for (const auto& event : events) {
        if (event.value("connection", std::size_t(-1)) != connection ||
            !event.contains("monotonic_ns"))
            continue;
        const auto kind = event.value("kind", "");
        const auto now = event.at("monotonic_ns").get<std::uint64_t>();
        if (kind == "IO_SEND_ENTER" || kind == "IO_RECV_ENTER") {
            if (begin)
                return nullptr;
            begin = now;
            expected_end = kind == "IO_SEND_ENTER" ? "IO_SEND_RETURN" : "IO_RECV_RETURN";
        } else if (kind == "IO_SEND_RETURN" || kind == "IO_RECV_RETURN") {
            if (!begin || kind != expected_end || now < *begin)
                return nullptr;
            total += now - *begin;
            begin.reset();
            expected_end.clear();
            found = true;
        }
    }
    return found && !begin ? Json(total) : Json(nullptr);
}

Json tcp_delta(const Json& summary) {
    Json result = {{"start", nullptr}, {"end", nullptr}, {"deltas", Json::object()},
                   {"delta_reasons", Json::object()}};
    if (!summary.is_object() || !summary.contains("tcp_start") ||
        !summary.contains("tcp_end") || !summary.at("tcp_start").is_object() ||
        !summary.at("tcp_end").is_object())
        return result;
    result["start"] = summary.at("tcp_start");
    result["end"] = summary.at("tcp_end");
    for (const char* field : {"total_retrans", "segs_out", "segs_in", "data_segs_out", "data_segs_in",
                              "bytes_acked", "bytes_received"}) {
        const auto& start = summary.at("tcp_start");
        const auto& end = summary.at("tcp_end");
        if (!start.contains(field) || !end.contains(field) || start.at(field).is_null() ||
            end.at(field).is_null()) {
            result["deltas"][field] = nullptr;
            result["delta_reasons"][field] = "counter_boundary_missing";
            continue;
        }
        const auto first = start.at(field).get<std::uint64_t>();
        const auto last = end.at(field).get<std::uint64_t>();
        result["deltas"][field] = last >= first ? Json(last - first) : Json(nullptr);
        result["delta_reasons"][field] = last >= first ? Json(nullptr) : Json("counter_decreased");
    }
    return result;
}

Json tcp_preparation_identity(const Json* summary) {
    if (summary == nullptr || !summary->contains("tcp_start") ||
        !summary->at("tcp_start").is_object())
        return {{"snd_mss", nullptr}, {"rcv_mss", nullptr}};
    const auto& start = summary->at("tcp_start");
    return {{"snd_mss", start.contains("snd_mss") ? start.at("snd_mss") : Json(nullptr)},
            {"rcv_mss", start.contains("rcv_mss") ? start.at("rcv_mss") : Json(nullptr)}};
}

bool tcp_preparation_complete(const Json& preparation) {
    if (!preparation.is_object())
        return false;
    for (const char* participant : {"lookup", "ca", "tls_client", "tls_server"}) {
        if (!preparation.contains(participant) || !preparation.at(participant).is_object())
            return false;
        for (const char* field : {"snd_mss", "rcv_mss"})
            if (!preparation.at(participant).contains(field) ||
                preparation.at(participant).at(field).is_null())
                return false;
    }
    return true;
}

const Json* tls_connection(const std::optional<Json>& header, std::size_t connection) {
    if (!header || !header->contains("connections") || !header->at("connections").is_array())
        return nullptr;
    for (const auto& item : header->at("connections"))
        if (item.value("index", std::size_t(-1)) == connection)
            return &item;
    return nullptr;
}

Json tls_context_identity(const Json& header) {
    if (!header.contains("loaded_context_size") ||
        (!header.at("loaded_context_size").is_number_unsigned() &&
         (!header.at("loaded_context_size").is_number_integer() ||
          header.at("loaded_context_size").get<std::int64_t>() < 0)))
        return {{"size", nullptr}, {"hash", nullptr}};
    const auto size = header.at("loaded_context_size").get<std::size_t>();
    if (size == 0)
        return {{"size", 0}, {"hash", ""}};
    if (!header.contains("loaded_context_hash") || !header.at("loaded_context_hash").is_string() ||
        header.at("loaded_context_hash").get<std::string>().empty())
        return {{"size", size}, {"hash", nullptr}};
    return {{"size", size}, {"hash", header.at("loaded_context_hash")}};
}

bool tls_context_identity_complete(const Json& context) {
    if (!context.is_object() || !context.contains("size") || !context.contains("hash") ||
        context.at("size").is_null() || context.at("hash").is_null() ||
        (!context.at("size").is_number_unsigned() && !context.at("size").is_number_integer()) ||
        !context.at("hash").is_string())
        return false;
    const auto size = context.at("size").get<std::size_t>();
    return size == 0 ? context.at("hash").get<std::string>().empty()
                     : !context.at("hash").get<std::string>().empty();
}

Json endpoint_identity(const std::optional<Json>& header, std::string_view role) {
    if (!header || !header->contains("config") || !header->at("config").is_object() ||
        !header->contains("declaration") || !header->at("declaration").is_object())
        return nullptr;
    const auto& config = header->at("config");
    const auto& declaration = header->at("declaration");
    const char* adapter = role == "client" ? "client_adapter" : "server_adapter";
    Json support = Json::object();
    const auto capabilities = header->value("capabilities", Json::object());
    for (const char* field : {"monotonic_clock", "thread_cpu_clock", "perf", "heap_tracking",
                              "affinity", "kernel_timestamp_configured"})
        support[field] = capabilities.contains(field) ? capabilities.at(field) : Json(nullptr);
    return {{"role", role}, {"adapter", config.value(adapter, Json(nullptr))},
            {"library", declaration.value("library", Json(nullptr))},
            {"library_version", declaration.value("version", Json(nullptr))},
            {"build_options", declaration.value("build_options", Json(nullptr))},
            {"environment_hash", header->value("environment_hash", Json(nullptr))},
            {"loaded_context", tls_context_identity(*header)},
            {"mode", header->value("mode", Json(nullptr))},
            {"pinned_cpu", header->value("pinned_cpu", Json(nullptr))},
            {"measurement_controls", {{"perf", config.value("perf", Json(nullptr))},
                                       {"isolate", config.value("isolate", Json(nullptr))},
                                       {"pin_cores", config.value("pin_cores", Json(nullptr))},
                                       {"kernel_timestamps", config.value("kernel_timestamps", Json(nullptr))},
                                       {"channel_observer", config.value("channel_observer", true)}}},
            {"support", support}};
}

bool endpoint_identity_complete(const Json& endpoint) {
    if (!endpoint.is_object())
        return false;
    for (const char* field : {"adapter", "library", "library_version", "build_options",
                              "environment_hash", "loaded_context", "mode",
                              "measurement_controls", "support"})
        if (!endpoint.contains(field) || endpoint.at(field).is_null() ||
            (endpoint.at(field).is_string() && endpoint.at(field).get<std::string>().empty()))
            return false;
    if (!tls_context_identity_complete(endpoint.at("loaded_context")))
        return false;
    for (const auto* object_name : {"measurement_controls", "support"})
        for (auto it = endpoint.at(object_name).begin(); it != endpoint.at(object_name).end(); ++it)
            if (it.value().is_null())
                return false;
    return true;
}

Json value_or_null(const Json& object, std::string_view key) {
    return object.contains(std::string(key)) ? object.at(std::string(key)) : Json(nullptr);
}

bool observed_socket_complete(const Json& socket) {
    if (!socket.is_object())
        return false;
    for (const char* field : {"nonblocking", "tcp_nodelay", "kernel_timestamps"})
        if (!socket.contains(field) || !socket.at(field).is_boolean())
            return false;
    for (const char* field : {"send_buffer", "receive_buffer"})
        if (!socket.contains(field) || !socket.at(field).is_number_integer() ||
            socket.at(field).get<std::int64_t>() <= 0)
            return false;
    return true;
}

Json all_socket_settings(const std::optional<Json>& header) {
    if (!header || !header->contains("connections") ||
        !header->at("connections").is_array())
        return nullptr;
    Json settings = Json::array();
    for (const auto& connection : header->at("connections"))
        settings.push_back(connection.value("socket", Json(nullptr)));
    return settings;
}

bool observed_socket_array_complete(const Json& settings) {
    if (!settings.is_array() || settings.empty())
        return false;
    for (const auto& socket : settings)
        if (!observed_socket_complete(socket))
            return false;
    return true;
}

bool connection_policy_complete(const Json& policy) {
    if (!policy.is_object())
        return false;
    for (const char* field : {"warmups", "connections", "tcp_nodelay", "socket_send_buffer",
                              "socket_receive_buffer", "timeout_ms", "failure_policy",
                              "flush_grace_ms"})
        if (!policy.contains(field) || policy.at(field).is_null())
            return false;
    return observed_socket_complete(policy.value("client_socket_actual", Json(nullptr))) &&
           observed_socket_complete(policy.value("server_socket_actual", Json(nullptr))) &&
           observed_socket_array_complete(
               policy.value("client_sockets_actual", Json(nullptr))) &&
           observed_socket_array_complete(
               policy.value("server_sockets_actual", Json(nullptr)));
}

bool volatile_identity_key(std::string_view key) {
    static constexpr std::string_view exact[] = {
        "pid",          "pids",       "fd",          "fds",       "path",
        "port",         "ports",      "handle",      "timestamp",
        "monotonic_ns", "namespace_pid", "namespace_inode", "time", "started_at",
        "ended_at",     "drops",      "drop",        "actual_drop", "retrans",
        "retransmits",  "total_retrans", "outcome",  "status",    "reason"};
    return std::find(std::begin(exact), std::end(exact), key) != std::end(exact);
}

Json stable_identity(const Json& value) {
    if (value.is_array()) {
        Json output = Json::array();
        for (const auto& item : value)
            output.push_back(stable_identity(item));
        return output;
    }
    if (!value.is_object())
        return value;
    Json output = Json::object();
    for (auto it = value.begin(); it != value.end(); ++it) {
        if (!volatile_identity_key(it.key()))
            output[it.key()] = stable_identity(it.value());
    }
    return output;
}

bool contains_identity_key(const Json& value, std::string_view key) {
    if (value.is_array()) {
        for (const auto& item : value)
            if (contains_identity_key(item, key))
                return true;
        return false;
    }
    if (!value.is_object())
        return false;
    if (value.contains(std::string(key)) && !value.at(std::string(key)).is_null())
        return true;
    for (auto it = value.begin(); it != value.end(); ++it)
        if (contains_identity_key(it.value(), key))
            return true;
    return false;
}

std::map<std::uint64_t, Attempt> ledger_attempts(const std::filesystem::path& root,
                                                  std::size_t& requested,
                                                  std::string& ledger_status) {
    std::map<std::uint64_t, Attempt> attempts;
    const auto path = root / "attempts.jsonl";
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(path, status_error);
    if (status_error && status_error != std::errc::no_such_file_or_directory)
        throw std::runtime_error("cannot inspect authoritative attempt ledger: " + path.string());
    if (status.type() == std::filesystem::file_type::not_found) {
        ledger_status = "absent_using_legacy_tls_and_director_fallback";
        return attempts;
    }
    const auto ledger = read_authoritative_ledger(path);
    requested = ledger.requested;
    ledger_status = ledger.partial ? "authoritative_partial" : "authoritative";
    for (std::size_t row_index = 1; row_index < ledger.rows.size(); ++row_index) {
        const auto& row = ledger.rows[row_index];
        const auto kind = row.value("record_kind", "");
        if (kind == "run_summary")
            continue;
        const auto id = row.at("attempt_id").get<std::uint64_t>();
        auto& attempt = attempts[id];
        attempt.id = id;
        attempt.started = row.value("started", true);
        attempt.connections = row.value("connections", Json::array());
        attempt.observation_ids = row.value("network_observation_ids", Json::array());
        attempt.legacy_artifact_status = row.value("artifact_status", Json::array());
        attempt.artifacts = row.contains("artifacts") && row.at("artifacts").is_object()
                                ? row.at("artifacts") : Json::object();
        if (kind == "attempt_final") {
            // A parent final row is authoritative. Child validity is never consulted here.
            attempt.status = row.value("final_status", "incomplete");
            attempt.failure_phase = row.value("failure_phase", "none");
            attempt.reason = row.value("reason", "");
        }
    }
    for (const auto& [id, validated] : ledger.attempts) {
        auto& attempt = attempts[id];
        attempt.id = id;
        attempt.started = validated.started;
        if (!validated.started) {
            attempt.status = "not_attempted";
        } else if (attempt.status == "not_attempted") {
            attempt.status = "incomplete";
            attempt.reason = "missing_attempt_final";
        }
    }
    return attempts;
}

std::optional<Json> tls_partition(const std::filesystem::path& path, std::size_t connection) {
    const auto rows = json_lines(path);
    if (rows.empty() || rows.front().value("type", "") != "sample" ||
        rows.front().value("schema", 0) != 1)
        return std::nullopt;
    std::vector<Json> events(rows.begin() + 1, rows.end());
    try {
        for (const auto& part : partition(rows.front(), events))
            if (part.value("connection", std::size_t(-1)) == connection)
                return part;
    } catch (const Json::exception&) {
    }
    return std::nullopt;
}

std::optional<Json> tls_header(const std::filesystem::path& path) {
    const auto rows = json_lines(path);
    if (!rows.empty() && rows.front().value("type", "") == "sample" &&
        rows.front().value("schema", 0) == 1)
        return rows.front();
    return std::nullopt;
}

std::vector<std::filesystem::path> sample_directories(const std::filesystem::path& root) {
    std::set<std::filesystem::path> directories;
    if (!std::filesystem::exists(root))
        return {};
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file())
            continue;
        const auto name = entry.path().filename();
        if (name == "lookup.jsonl" || name == "ca.jsonl" || name == "client.jsonl" ||
            name == "server.jsonl" || name == "director.txt")
            directories.insert(entry.path().parent_path());
    }
    return {directories.begin(), directories.end()};
}

std::uint64_t sample_id(const Artifact& lookup, const std::optional<Json>& client,
                        const std::optional<Json>& server) {
    if (lookup.header.contains("sample"))
        return lookup.header.at("sample").get<std::uint64_t>();
    if (client && client->contains("sample"))
        return client->at("sample").get<std::uint64_t>();
    if (server && server->contains("sample"))
        return server->at("sample").get<std::uint64_t>();
    return 0;
}

std::string legacy_status(const std::filesystem::path& directory,
                          const std::optional<Json>& client, const std::optional<Json>& server,
                          std::string& reason) {
    std::ifstream director(directory / "director.txt");
    std::string line;
    if (director && (!std::getline(director, line) || line != "valid")) {
        reason = line.empty() ? "director status is empty" : line;
        return "error";
    }
    if (!client || !server) {
        reason = "legacy TLS role artifact missing";
        return "incomplete";
    }
    if (!client->value("valid", false) || !server->value("valid", false)) {
        reason = "legacy child marked invalid";
        return "error";
    }
    return "success";
}

Json status_counts(const std::map<std::uint64_t, Attempt>& attempts, std::size_t requested) {
    Json counts = {{"requested", requested}, {"started", 0}, {"success", 0},
                   {"timeout", 0},           {"error", 0},   {"incomplete", 0},
                   {"not_attempted", 0}};
    for (const auto& [id, attempt] : attempts) {
        (void)id;
        if (attempt.started)
            counts["started"] = counts["started"].get<std::size_t>() + 1;
        const auto status = attempt.status;
        if (counts.contains(status))
            counts[status] = counts[status].get<std::size_t>() + 1;
    }
    return counts;
}

Json metric_distribution(const std::vector<double>& values) {
    if (values.empty())
        return {{"count", 0}, {"minimum", nullptr}, {"maximum", nullptr},
                {"stq1", nullptr}, {"stq2", nullptr}, {"stq3", nullptr},
                {"values", Json::array()}};
    const auto value = statistics(values);
    return {{"count", value.count}, {"minimum", value.minimum}, {"maximum", value.maximum},
            {"stq1", value.stq[0]}, {"stq2", value.stq[1]}, {"stq3", value.stq[2]},
            {"values", values}};
}
} // namespace

Json summarize_lookup_run(const std::filesystem::path& input) {
    const auto root = std::filesystem::is_regular_file(input) ? input.parent_path() : input;
    std::size_t requested = 0;
    std::string ledger_status;
    auto attempts = ledger_attempts(root, requested, ledger_status);

    struct SampleArtifacts {
        std::filesystem::path directory;
        Artifact lookup;
        Artifact ca;
        std::optional<Json> client;
        std::optional<Json> server;
    };
    std::map<std::uint64_t, SampleArtifacts> samples;
    for (const auto& directory : sample_directories(root)) {
        auto lookup = read_artifact(directory / "lookup.jsonl", "certificate-lookup");
        auto ca = read_artifact(directory / "ca.jsonl", "mock-ca");
        auto client = tls_header(directory / "client.jsonl");
        auto server = tls_header(directory / "server.jsonl");
        const auto id = sample_id(lookup, client, server);
        if (id == 0)
            continue;
        samples[id] = {directory, std::move(lookup), std::move(ca), std::move(client),
                       std::move(server)};
    }

    if (attempts.empty()) {
        for (const auto& [id, sample] : samples) {
            Attempt attempt;
            attempt.id = id;
            attempt.started = true;
            attempt.source = "legacy_tls_director_fallback";
            attempt.status = legacy_status(sample.directory, sample.client, sample.server,
                                           attempt.reason);
            if (sample.client && sample.client->contains("connections"))
                for (const auto& connection : sample.client->at("connections"))
                    attempt.connections.push_back(connection.at("index"));
            attempts[id] = std::move(attempt);
        }
        requested = attempts.size();
    }

    std::vector<NetworkAttempt> network_attempts;
    network_attempts.reserve(attempts.size());
    for (const auto& [id, attempt] : attempts)
        network_attempts.push_back(
            {id, attempt.started, attempt.status, attempt.observation_ids});
    const auto network = read_network_evidence(
        root, NetworkTopology::lookup_4ns, network_attempts);
    const auto& network_identity = network.condition_identity;
    const auto& network_observations = network.observations;
    const auto& run_network_integrity = network.integrity;

    Json joined = Json::array();
    Json connection_table = Json::array();
    Json attempt_table = Json::array();
    std::map<std::string, Json> groups;
    std::map<std::uint64_t, std::vector<std::size_t>> attempt_row_refs;

    for (auto& [id, attempt] : attempts) {
        auto sample_it = samples.find(id);
        Json connections = attempt.connections;
        if (connections.empty() && sample_it != samples.end()) {
            std::set<std::size_t> indices;
            for (const auto& [index, summary] : sample_it->second.lookup.connections) {
                (void)summary;
                indices.insert(index);
            }
            if (sample_it->second.client)
                for (const auto& connection : sample_it->second.client->value("connections", Json::array()))
                    indices.insert(connection.at("index").get<std::size_t>());
            for (const auto index : indices)
                connections.push_back(index);
        }

        for (const auto& connection_value : connections) {
            const auto connection = connection_value.get<std::size_t>();
            Json row = {{"attempt_id", id},
                        {"connection", connection},
                        {"attempt_status", attempt.status},
                        {"network_observation_ids", attempt.observation_ids},
                        {"qdisc_aggregate_ownership", "shared_observation_reference_only"}};
            row["network_observation_reference_status"] = Json::array();
            auto row_network_integrity = run_network_integrity;
            bool network_required = network.present;
            if (sample_it != samples.end() && sample_it->second.client &&
                sample_it->second.client->contains("config") &&
                sample_it->second.client->at("config").is_object() &&
                sample_it->second.client->at("config").contains("network_handoff") &&
                !sample_it->second.client->at("config").at("network_handoff").is_null())
                network_required = true;
            row_network_integrity["required"] = network_required;
            if (!network_required) {
                row_network_integrity["status"] = "not_applicable_loopback";
                row_network_integrity["eligible"] = true;
                row_network_integrity["reasons"] = Json::array();
            }
            if (attempt.observation_ids.empty()) {
                if (network_required) {
                    row_network_integrity["eligible"] = false;
                    row_network_integrity["status"] = "failed";
                    row_network_integrity["reasons"].push_back("network_observation_references_missing");
                }
            }
            for (const auto& observation_id : attempt.observation_ids) {
                const auto id_value = observation_id.get<std::string>();
                bool present = network_observations.contains(id_value);
                if (present) {
                    const auto& observation = network_observations.at(id_value);
                    const auto canonical = std::to_string(id) + ":" +
                                           observation.value("phase", "") + ":" +
                                           observation.value("edge", "");
                    const bool trace_required =
                        row_network_integrity.contains("trace_requested") &&
                        row_network_integrity.at("trace_requested").is_boolean() &&
                        row_network_integrity.at("trace_requested").get<bool>();
                    present = observation.value("attempt", std::uint64_t{0}) == id &&
                              canonical == id_value && observation.contains("qdiscs") &&
                              observation.at("qdiscs").is_object() &&
                              !observation.at("qdiscs").empty() &&
                              (!trace_required || (observation.contains("packet_trace") &&
                                                   !observation.at("packet_trace").is_null()));
                }
                row["network_observation_reference_status"].push_back(
                    {{"observation_id", id_value},
                     {"present", present}});
                if (network_required && !present) {
                    row_network_integrity["eligible"] = false;
                    row_network_integrity["status"] = "failed";
                    row_network_integrity["reasons"].push_back(
                        "referenced_network_observation_missing:" + id_value);
                }
            }
            if (network_required && attempt.status == "success") {
                std::set<std::string> expected, actual;
                for (const char* phase : {"setup", "scenario", "cleanup"})
                    for (const char* edge : {"begin", "end"})
                        expected.insert(std::to_string(id) + ":" + phase + ":" + edge);
                for (const auto& observation_id : attempt.observation_ids)
                    if (observation_id.is_string())
                        actual.insert(observation_id.get<std::string>());
                if (actual != expected || attempt.observation_ids.size() != expected.size()) {
                    row_network_integrity["eligible"] = false;
                    row_network_integrity["status"] = "failed";
                    row_network_integrity["reasons"].push_back(
                        "successful_attempt_requires_exact_six_phase_observations");
                }
            }
            row["network_integrity"] = row_network_integrity;
            row["descriptive_distribution_eligible"] =
                !network_required || row_network_integrity.value("eligible", false);
            bool warmup = false;
            if (sample_it != samples.end() && sample_it->second.lookup.connections.contains(connection))
                warmup = sample_it->second.lookup.connections.at(connection).value("warmup", false);
            else if (sample_it != samples.end() && sample_it->second.client)
                for (const auto& item : sample_it->second.client->value("connections", Json::array()))
                    if (item.value("index", std::size_t(-1)) == connection)
                        warmup = item.value("warmup", false);
            row["warmup"] = warmup;

            const Artifact* lookup = sample_it == samples.end() ? nullptr : &sample_it->second.lookup;
            const Artifact* ca = sample_it == samples.end() ? nullptr : &sample_it->second.ca;
            const Json* lookup_summary = nullptr;
            const Json* ca_summary = nullptr;
            if (lookup && lookup->connections.contains(connection))
                lookup_summary = &lookup->connections.at(connection);
            if (ca && ca->connections.contains(connection))
                ca_summary = &ca->connections.at(connection);
            const bool hit = lookup_summary && lookup_summary->value("cache_hit", false);
            row["cache_hit"] = hit;
            row["request_count"] = lookup_summary
                                       ? Json(lookup_summary->value("request_count", 0))
                                       : Json(nullptr);
            row["lookup_artifact"] = lookup_summary ? Json({
                {"status", lookup_summary->value("artifact_status", "missing")},
                {"object_id", lookup_summary->value("object_id", Json(nullptr))},
                {"object_size", lookup_summary->value("object_size", Json(nullptr))},
                {"logical_cache_bytes", lookup_summary->value("logical_cache_bytes", Json(nullptr))},
                {"cache_capacity", lookup_summary->value("cache_capacity", Json(nullptr))},
                {"reference_bytes", lookup_summary->value("reference_bytes", Json(nullptr))},
                {"framework_reserved_bytes", lookup_summary->value("framework_reserved_bytes", Json(nullptr))}})
                                                     : Json(nullptr);
            row["ca_artifact"] = ca_summary ? Json({
                {"status", ca_summary->value("artifact_status", "missing")},
                {"object_id", ca_summary->value("object_id", Json(nullptr))},
                {"object_size", ca_summary->value("object_size", Json(nullptr))},
                {"framework_reserved_bytes", ca_summary->value("framework_reserved_bytes", Json(nullptr))}})
                                             : Json(nullptr);

            if (hit) {
                row["remote_lookup_duration_ns"] = nullptr;
                row["remote_lookup_duration_reason"] = "not_applicable_cache_hit";
            } else {
                duration(row, "remote_lookup_duration",
                         lookup ? timestamp(lookup->events, connection, "REQUEST_BEGIN") : std::nullopt,
                         lookup ? timestamp(lookup->events, connection, "RESPONSE_COMPLETE", true)
                                : std::nullopt,
                         "missing_lookup_request_or_response_boundary");
            }
            duration(row, "usable_duration",
                     lookup ? timestamp(lookup->events, connection,
                                        hit ? "CACHE_LOOKUP" : "REQUEST_BEGIN") : std::nullopt,
                     lookup ? timestamp(lookup->events, connection, "USABLE_OBJECT", true)
                            : std::nullopt,
                     hit ? "missing_cache_lookup_or_usable_boundary"
                         : "missing_lookup_request_or_usable_boundary");
            duration(row, "scenario_elapsed",
                     lookup ? timestamp(lookup->events, connection, "SCENARIO_BEGIN") : std::nullopt,
                     lookup ? timestamp(lookup->events, connection, "SCENARIO_END", true)
                            : std::nullopt,
                     "missing_scenario_boundary");
            duration(row, "ca_process",
                     ca ? timestamp(ca->events, connection, "CA_PROCESS_BEGIN") : std::nullopt,
                     ca ? timestamp(ca->events, connection, "CA_PROCESS_END", true) : std::nullopt,
                     hit ? "not_applicable_cache_hit" : "missing_ca_process_boundary");
            duration(row, "ca_cpu",
                     ca ? cpu_timestamp(ca->events, connection, "CA_PROCESS_BEGIN") : std::nullopt,
                     ca ? cpu_timestamp(ca->events, connection, "CA_PROCESS_END", true) : std::nullopt,
                     hit ? "not_applicable_cache_hit" : "missing_ca_cpu_boundary");
            row["ca_io_ns"] = ca ? io_interval_sum(ca->events, connection)
                                   : Json(nullptr);
            row["ca_io_reason"] = row["ca_io_ns"].is_null()
                                      ? Json(hit ? "not_applicable_cache_hit" : "missing_or_unpaired_ca_io_boundary")
                                      : Json(nullptr);
            row["ca_wait_ns"] = ca ? interval_sum(ca->events, connection, "WAIT_BEGIN", "WAIT_END")
                                     : Json(nullptr);
            row["ca_wait_reason"] = row["ca_wait_ns"].is_null()
                                        ? Json(hit ? "not_applicable_cache_hit" : "missing_or_unpaired_ca_wait_boundary")
                                        : Json(nullptr);

            std::optional<Json> tls;
            if (sample_it != samples.end())
                tls = tls_partition(sample_it->second.directory / "client.jsonl", connection);
            if (tls && tls->value("valid", false)) {
                row["tls_elapsed_ns"] = tls->at("elapsed_ns");
                row["tls_elapsed_reason"] = nullptr;
            } else {
                row["tls_elapsed_ns"] = nullptr;
                row["tls_elapsed_reason"] = tls ? tls->value("reason", "invalid_tls_boundaries")
                                                : "missing_tls_artifact_or_connection";
            }
            const Json* client_connection = sample_it == samples.end()
                                                ? nullptr
                                                : tls_connection(sample_it->second.client, connection);
            const Json* server_connection = sample_it == samples.end()
                                                ? nullptr
                                                : tls_connection(sample_it->second.server, connection);
            row["tcp_counter_deltas"] = {
                {"lookup", lookup_summary ? tcp_delta(*lookup_summary) : Json(nullptr)},
                {"ca", ca_summary ? tcp_delta(*ca_summary) : Json(nullptr)},
                {"tls_client", client_connection ? tcp_delta(*client_connection) : Json(nullptr)},
                {"tls_server", server_connection ? tcp_delta(*server_connection) : Json(nullptr)}};

            const bool lookup_complete = lookup_summary &&
                lookup_summary->value("artifact_status", "missing") == "complete";
            const bool ca_complete = hit || (ca_summary &&
                ca_summary->value("artifact_status", "missing") == "complete");
            const bool tls_complete = tls && tls->value("valid", false);
            row["connection_status"] = lookup_complete && ca_complete && tls_complete
                                           ? "success" : "incomplete";

            Json identity = {{"scenario_name", lookup && lookup->header.contains("scenario_name")
                                                   ? lookup->header.at("scenario_name") : Json(nullptr)},
                             {"synthetic_scenario", lookup && lookup->header.value("scenario_name", "") ==
                                                       "synthetic-lookup-plus-standard-tls"},
                             {"cache_mode", lookup && lookup->header.contains("cache_mode")
                                                ? lookup->header.at("cache_mode") : Json(nullptr)},
                             {"cache_state_id", lookup && lookup->header.contains("cache_state_id")
                                                    ? lookup->header.at("cache_state_id") : Json(nullptr)},
                             {"object_id", lookup && lookup->header.contains("object_id")
                                               ? lookup->header.at("object_id") : Json(nullptr)},
                             {"object_size", lookup && lookup->header.contains("object_size")
                                                 ? lookup->header.at("object_size") : Json(nullptr)},
                             {"initial_cache_bytes", lookup && lookup->header.contains("initial_cache_bytes")
                                                         ? lookup->header.at("initial_cache_bytes") : Json(nullptr)},
                             {"initial_cache_capacity", lookup && lookup->header.contains("cache_capacity")
                                                            ? lookup->header.at("cache_capacity") : Json(nullptr)},
                             {"reference_bytes", lookup && lookup->header.contains("reference_bytes")
                                                     ? lookup->header.at("reference_bytes") : Json(nullptr)},
                             {"ca_object_id", ca && ca->header.contains("object_id")
                                                   ? ca->header.at("object_id") : Json(nullptr)},
                             {"ca_object_size", ca && ca->header.contains("object_size")
                                                     ? ca->header.at("object_size") : Json(nullptr)},
                             {"observation_level", lookup && lookup->header.contains("observation_level")
                                                       ? lookup->header.at("observation_level") : Json(nullptr)},
                             {"ca_observation_level", ca && ca->header.contains("observation_level")
                                                          ? ca->header.at("observation_level") : Json(nullptr)},
                             {"lookup_pinned_cpu", lookup && lookup->header.contains("pinned_cpu")
                                                       ? lookup->header.at("pinned_cpu") : Json(nullptr)},
                             {"ca_pinned_cpu", ca && ca->header.contains("pinned_cpu")
                                                   ? ca->header.at("pinned_cpu") : Json(nullptr)},
                             {"mode", lookup && lookup->header.contains("mode")
                                          ? lookup->header.at("mode") : Json(nullptr)},
                             {"connection_position", connection},
                             {"warmup", warmup},
                             {"network", network_identity}};
            identity["tcp_preparation"] = {
                {"lookup", tcp_preparation_identity(lookup_summary)},
                {"ca", tcp_preparation_identity(ca_summary)},
                {"tls_client", tcp_preparation_identity(client_connection)},
                {"tls_server", tcp_preparation_identity(server_connection)}};
            if (sample_it != samples.end() && sample_it->second.client) {
                const auto& header = *sample_it->second.client;
                identity["connection_policy"] = {{"warmups", value_or_null(header.at("config"), "warmups")},
                                                   {"connections", value_or_null(header.at("config"), "connections")},
                                                   {"tcp_nodelay", value_or_null(header.at("config"), "tcp_nodelay")},
                                                   {"socket_send_buffer", value_or_null(header.at("config"), "socket_send_buffer")},
                                                   {"socket_receive_buffer", value_or_null(header.at("config"), "socket_receive_buffer")},
                                                   {"timeout_ms", value_or_null(header.at("config"), "timeout_ms")},
                                                   {"failure_policy", value_or_null(header.at("config"), "failure_policy")},
                                                   {"flush_grace_ms", value_or_null(header.at("config"), "flush_grace_ms")},
                                                   {"client_socket_actual", client_connection && client_connection->contains("socket")
                                                                                ? client_connection->at("socket") : Json(nullptr)},
                                                   {"server_socket_actual", server_connection && server_connection->contains("socket")
                                                                                ? server_connection->at("socket") : Json(nullptr)},
                                                   {"client_sockets_actual", all_socket_settings(sample_it->second.client)},
                                                   {"server_sockets_actual", all_socket_settings(sample_it->second.server)}};
                identity["tls_profile_hash"] = header.value("profile_hash", Json(nullptr));
                identity["client_observation_level"] = header.value("observation_level", Json(nullptr));
                identity["scenario_name"] = lookup && lookup->header.contains("scenario_name")
                                                ? lookup->header.at("scenario_name")
                                                : header.at("config").value("scenario_name", Json(nullptr));
                identity["client_pinned_cpu"] = header.value("pinned_cpu", Json(nullptr));
                identity["client_endpoint"] = endpoint_identity(sample_it->second.client, "client");
                identity["server_endpoint"] = endpoint_identity(sample_it->second.server, "server");
            } else {
                identity["connection_policy"] = nullptr;
                identity["tls_profile_hash"] = nullptr;
                identity["client_pinned_cpu"] = nullptr;
                identity["client_endpoint"] = nullptr;
                identity["server_endpoint"] = nullptr;
            }
            identity["server_pinned_cpu"] = sample_it != samples.end() && sample_it->second.server
                                                  ? sample_it->second.server->value("pinned_cpu", Json(nullptr))
                                                  : Json(nullptr);
            identity["server_observation_level"] = sample_it != samples.end() && sample_it->second.server
                                                        ? sample_it->second.server->value("observation_level", Json(nullptr))
                                                        : Json(nullptr);
            identity = stable_identity(identity);
            Json missing_identity = Json::array();
            for (const char* key : {"scenario_name", "cache_mode", "cache_state_id", "object_id",
                                    "object_size", "initial_cache_bytes", "initial_cache_capacity",
                                    "reference_bytes", "observation_level", "ca_observation_level",
                                    "ca_object_id", "ca_object_size", "network", "mode",
                                    "connection_position", "warmup", "connection_policy",
                                    "tls_profile_hash", "client_endpoint", "server_endpoint",
                                    "tcp_preparation"})
                if (!identity.contains(key) || identity.at(key).is_null() ||
                    (identity.at(key).is_object() && identity.at(key).empty()))
                    missing_identity.push_back(key);
            if (!network_identity.is_object() ||
                !contains_identity_key(network_identity, "topology") ||
                !contains_identity_key(network_identity, "mtu") ||
                !(contains_identity_key(network_identity, "offloads") ||
                  contains_identity_key(network_identity, "offload")) ||
                !contains_identity_key(network_identity, "requested") ||
                !contains_identity_key(network_identity, "actual"))
                missing_identity.push_back("network_identity_incomplete");
            if (!client_connection || !client_connection->contains("socket") ||
                !observed_socket_complete(client_connection->at("socket")) || !server_connection ||
                !server_connection->contains("socket") ||
                !observed_socket_complete(server_connection->at("socket")))
                missing_identity.push_back("tcp_preparation_actual_missing");
            if (!connection_policy_complete(identity.at("connection_policy")))
                missing_identity.push_back("connection_policy_incomplete");
            if (!tcp_preparation_complete(identity.at("tcp_preparation")))
                missing_identity.push_back("tcp_start_mss_missing");
            if (!endpoint_identity_complete(identity.at("client_endpoint")) ||
                !endpoint_identity_complete(identity.at("server_endpoint")))
                missing_identity.push_back("endpoint_identity_incomplete");
            row["condition_identity"] = identity;
            row["automatic_comparison_eligible"] =
                missing_identity.empty() && row_network_integrity.value("eligible", false);
            row["comparison_exclusion_reasons"] = Json::array();
            for (const auto& key : missing_identity)
                row["comparison_exclusion_reasons"].push_back("missing_identity:" + key.get<std::string>());
            for (const auto& reason : row_network_integrity.at("reasons"))
                row["comparison_exclusion_reasons"].push_back(
                    "network_integrity:" + reason.get<std::string>());

            const auto row_index = joined.size();
            joined.push_back(row);
            attempt_row_refs[id].push_back(row_index);
            connection_table.push_back({{"attempt_id", id}, {"connection", connection},
                                        {"warmup", warmup},
                                        {"status", row["connection_status"]},
                                        {"joined_row", row_index}});
            const auto group_key = identity.dump();
            auto& group = groups[group_key];
            if (group.is_null())
                group = {{"condition_identity", identity}, {"joined_rows", Json::array()},
                         {"automatic_comparison_eligible", row["automatic_comparison_eligible"]},
                         {"timing_interpretation", lookup && lookup->header.value("mode", "timing") == "timing"
                                                       ? "performance" : "diagnostic_only"}};
            group["automatic_comparison_eligible"] =
                group.value("automatic_comparison_eligible", false) &&
                row.value("automatic_comparison_eligible", false);
            group["joined_rows"].push_back(row_index);
        }
    }

    for (const auto& [id, attempt] : attempts) {
        Json refs = Json::array();
        for (const auto ref : attempt_row_refs[id])
            refs.push_back(ref);
        attempt_table.push_back({{"attempt_id", id}, {"started", attempt.started},
                                 {"final_status", attempt.status},
                                 {"failure_phase", attempt.failure_phase},
                                 {"reason", attempt.reason}, {"source", attempt.source},
                                 {"artifacts", attempt.artifacts},
                                 {"artifact_status", attempt.legacy_artifact_status},
                                 {"network_observation_ids", attempt.observation_ids},
                                 {"connection_rows", refs}});
    }
    Json condition_groups = Json::array();
    for (auto& [key, group] : groups) {
        (void)key;
        group["distributions"] = Json::object();
        for (const char* metric : {"remote_lookup_duration_ns", "usable_duration_ns",
                                   "tls_elapsed_ns", "scenario_elapsed_ns", "ca_process_ns",
                                   "ca_cpu_ns", "ca_io_ns", "ca_wait_ns"}) {
            std::vector<double> values;
            if (group.value("timing_interpretation", "diagnostic_only") == "performance") {
                for (const auto& reference : group.at("joined_rows")) {
                    const auto& row = joined.at(reference.get<std::size_t>());
                    if (row.value("warmup", false) ||
                        !row.value("descriptive_distribution_eligible", false) ||
                        row.value("attempt_status", "") != "success" ||
                        row.value("connection_status", "") != "success" ||
                        !row.contains(metric) || row.at(metric).is_null())
                        continue;
                    values.push_back(row.at(metric).get<double>());
                }
            }
            group["distributions"][metric] = metric_distribution(values);
        }
        condition_groups.push_back(std::move(group));
    }
    const auto counts = status_counts(attempts, requested);
    if (counts.at("requested").get<std::size_t>() !=
            counts.at("started").get<std::size_t>() + counts.at("not_attempted").get<std::size_t>() ||
        counts.at("started").get<std::size_t>() != counts.at("success").get<std::size_t>() +
            counts.at("timeout").get<std::size_t>() + counts.at("error").get<std::size_t>() +
            counts.at("incomplete").get<std::size_t>())
        throw std::runtime_error("attempt ledger denominator identities are inconsistent");

    Json result = {{"type", "turtle-lookup-summary"}, {"schema", 1},
                   {"scenario_disclosure", "synthetic lookup plus stock certificate-based TLS; not a certificate-lightening result"},
                   {"attempt_ledger_status", ledger_status}, {"denominators", counts},
                   {"network_integrity", run_network_integrity},
                   {"condition_groups", condition_groups}, {"attempt_table", attempt_table},
                   {"connection_table", connection_table}, {"joined_rows", joined},
                   {"network_observations", network_observations},
                   {"aggregation_rules", {{"ca_plus_rtt", "never_summed"},
                                           {"qdisc_per_connection", "reference_only_never_summed"},
                                           {"memory_mode_timing", "diagnostic_only"}}}};
    return result;
}

Json summarize_lookup(const std::filesystem::path& input, const std::filesystem::path& output) {
    const auto root = std::filesystem::is_regular_file(input) ? input.parent_path() : input;
    std::vector<std::filesystem::path> runs;
    std::error_code ledger_status_error;
    const auto root_ledger_status =
        std::filesystem::symlink_status(root / "attempts.jsonl", ledger_status_error);
    if (ledger_status_error &&
        ledger_status_error != std::errc::no_such_file_or_directory)
        throw std::runtime_error("cannot inspect authoritative attempt ledger: " +
                                 (root / "attempts.jsonl").string());
    if (root_ledger_status.type() != std::filesystem::file_type::not_found) {
        runs.push_back(root);
    } else if (std::filesystem::exists(root)) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root))
            if (entry.path().filename() == "attempts.jsonl") {
                if (!entry.is_regular_file())
                    throw std::runtime_error(
                        "authoritative attempt ledger is not a regular file: " +
                        entry.path().string());
                runs.push_back(entry.path().parent_path());
            }
    }
    if (runs.empty())
        runs.push_back(root);
    std::sort(runs.begin(), runs.end());

    Json combined = {{"type", "turtle-lookup-summary"}, {"schema", 1},
                     {"scenario_disclosure", "synthetic lookup plus stock certificate-based TLS; not a certificate-lightening result"},
                     {"attempt_ledger_status", runs.size() == 1 ? Json(nullptr) : Json("multiple_authoritative_ledgers")},
                     {"denominators", {{"requested", 0}, {"started", 0}, {"success", 0},
                                       {"timeout", 0}, {"error", 0}, {"incomplete", 0},
                                       {"not_attempted", 0}}},
                     {"condition_groups", Json::array()}, {"attempt_table", Json::array()},
                     {"connection_table", Json::array()}, {"joined_rows", Json::array()},
                     {"network_observations", Json::object()},
                     {"network_integrity", Json::array()},
                     {"aggregation_rules", {{"ca_plus_rtt", "never_summed"},
                                             {"qdisc_per_connection", "reference_only_never_summed"},
                                             {"memory_mode_timing", "diagnostic_only"}}}};
    std::map<std::string, std::size_t> group_indices;
    for (const auto& run : runs) {
        auto report = summarize_lookup_run(run);
        std::error_code ec;
        auto relative = std::filesystem::relative(run, root, ec);
        const std::string run_id = ec || relative.empty() || relative == "." ? "." : relative.generic_string();
        if (runs.size() == 1)
            combined["attempt_ledger_status"] = report.at("attempt_ledger_status");
        combined["network_integrity"].push_back(
            {{"run_id", run_id}, {"integrity", report.at("network_integrity")}});
        for (auto it = combined["denominators"].begin(); it != combined["denominators"].end(); ++it)
            it.value() = it.value().get<std::size_t>() +
                         report.at("denominators").at(it.key()).get<std::size_t>();
        const auto offset = combined["joined_rows"].size();
        for (auto row : report.at("joined_rows")) {
            row["run_id"] = run_id;
            combined["joined_rows"].push_back(std::move(row));
        }
        for (auto row : report.at("attempt_table")) {
            row["run_id"] = run_id;
            for (auto& reference : row["connection_rows"])
                reference = reference.get<std::size_t>() + offset;
            combined["attempt_table"].push_back(std::move(row));
        }
        for (auto row : report.at("connection_table")) {
            row["run_id"] = run_id;
            row["joined_row"] = row["joined_row"].get<std::size_t>() + offset;
            combined["connection_table"].push_back(std::move(row));
        }
        for (auto it = report.at("network_observations").begin();
             it != report.at("network_observations").end(); ++it)
            combined["network_observations"][run_id + ":" + it.key()] =
                {{"run_id", run_id}, {"observation", it.value()}};
        for (auto group : report.at("condition_groups")) {
            const auto key = group.at("condition_identity").dump();
            if (!group_indices.contains(key)) {
                const auto index = combined["condition_groups"].size();
                group_indices[key] = index;
                group["joined_rows"] = Json::array();
                combined["condition_groups"].push_back(std::move(group));
            }
            auto& target = combined["condition_groups"][group_indices.at(key)];
            // Re-find this source group's references after the target may have been moved.
            for (const auto& source_group : report.at("condition_groups")) {
                if (source_group.at("condition_identity").dump() != key)
                    continue;
                for (const auto& reference : source_group.at("joined_rows"))
                    target["joined_rows"].push_back(reference.get<std::size_t>() + offset);
                break;
            }
        }
    }
    // Recompute merged distributions from joined rows instead of combining per-run percentiles.
    for (auto& group : combined["condition_groups"]) {
        bool group_eligible = true;
        for (const auto& reference : group.at("joined_rows"))
            group_eligible = group_eligible &&
                combined["joined_rows"].at(reference.get<std::size_t>())
                    .value("automatic_comparison_eligible", false);
        group["automatic_comparison_eligible"] = group_eligible;
        for (const char* metric : {"remote_lookup_duration_ns", "usable_duration_ns", "tls_elapsed_ns",
                                   "scenario_elapsed_ns", "ca_process_ns", "ca_cpu_ns", "ca_io_ns", "ca_wait_ns"}) {
            std::vector<double> values;
            if (group.value("timing_interpretation", "diagnostic_only") == "performance")
                for (const auto& reference : group.at("joined_rows")) {
                    const auto& row = combined["joined_rows"].at(reference.get<std::size_t>());
                    if (!row.value("warmup", false) &&
                        row.value("descriptive_distribution_eligible", false) &&
                        row.value("attempt_status", "") == "success" &&
                        row.value("connection_status", "") == "success" && row.contains(metric) &&
                        !row.at(metric).is_null())
                        values.push_back(row.at(metric).get<double>());
                }
            group["distributions"][metric] = metric_distribution(values);
        }
    }
    std::filesystem::create_directories(output);
    std::ofstream file(output / "lookup-summary.json");
    file.exceptions(std::ios::badbit | std::ios::failbit);
    file << combined.dump(2) << '\n';
    return combined;
}
} // namespace turtle::report
