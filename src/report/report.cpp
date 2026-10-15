#include "report/report.hpp"
#include "report/window.hpp"
#include "report/network_evidence.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
namespace turtle::report {
namespace {
using Json = nlohmann::json;

Json measurement_contract_revision(const Json& header) {
    if (!header.contains("measurement_contract_revision"))
        return nullptr;
    const auto& value = header.at("measurement_contract_revision");
    if (value.is_number_unsigned() && value.get<std::uint64_t>() > 0)
        return value;
    if (value.is_number_integer() && value.get<std::int64_t>() > 0)
        return value;
    return nullptr;
}

std::optional<Json> read_json(const std::filesystem::path& path, std::string& reason) {
    std::ifstream file(path);
    if (!file) {
        reason = "sidecar_unreadable";
        return std::nullopt;
    }
    try {
        Json value;
        file >> value;
        return value;
    } catch (const Json::exception&) {
        reason = "malformed_json";
        return std::nullopt;
    }
}

std::optional<std::map<std::size_t, Json>>
decoded_connections(const Json& header, const Json& decoded, std::string& reason) {
    if (decoded.value("schema", 0) != 1) {
        reason = "unsupported_schema";
        return std::nullopt;
    }
    if (!decoded.contains("sample") || decoded.at("sample") != header.at("sample")) {
        reason = "sample_mismatch";
        return std::nullopt;
    }
    if (!decoded.contains("role") || decoded.at("role") != header.at("role")) {
        reason = "role_mismatch";
        return std::nullopt;
    }
    if (!decoded.contains("connections") || !decoded.at("connections").is_array()) {
        reason = "connections_missing";
        return std::nullopt;
    }
    std::map<std::size_t, Json> by_index;
    for (const auto& connection : decoded.at("connections")) {
        if (!connection.contains("connection")) {
            reason = "connection_index_missing";
            return std::nullopt;
        }
        const auto index = connection.at("connection").get<std::size_t>();
        if (!by_index.emplace(index, connection).second) {
            reason = "duplicate_connection";
            return std::nullopt;
        }
        if (!connection.value("decryption_complete", false)) {
            reason = "decryption_incomplete";
            return std::nullopt;
        }
    }
    if (by_index.size() != header.at("connections").size()) {
        reason = "connection_set_mismatch";
        return std::nullopt;
    }
    for (const auto& connection : header.at("connections")) {
        if (!by_index.contains(connection.at("index").get<std::size_t>())) {
            reason = "connection_set_mismatch";
            return std::nullopt;
        }
    }
    return by_index;
}

struct PeerHeader {
    bool verified = false;
    std::string reason;
    Json header;
};

Json socket_settings(const Json& header) {
    Json settings = Json::array();
    for (const auto& connection : header.value("connections", Json::array()))
        settings.push_back(connection.value("socket", Json(nullptr)));
    return settings;
}

bool observed_sockets(const Json& settings) {
    if (!settings.is_array() || settings.empty())
        return false;
    for (const auto& socket : settings) {
        if (!socket.is_object())
            return false;
        for (const auto* key : {"nonblocking", "tcp_nodelay", "kernel_timestamps"})
            if (!socket.contains(key) || !socket.at(key).is_boolean())
                return false;
        for (const auto* key : {"send_buffer", "receive_buffer"})
            if (!socket.contains(key) || !socket.at(key).is_number_integer() || socket.at(key) <= 0)
                return false;
    }
    return true;
}

Json context_identity(const Json& header) {
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

PeerHeader peer_header(const std::filesystem::path& path, const Json& header) {
    const auto role = header.at("role").get<std::string>();
    const auto expected_role = role == "client" ? "server" : "client";
    const auto peer_path = path.parent_path() / (std::string(expected_role) + ".jsonl");
    std::ifstream file(peer_path);
    if (!file) {
        return {false, "peer_file_absent", Json::object()};
    }
    std::string line;
    if (!std::getline(file, line)) {
        return {false, "peer_header_missing", Json::object()};
    }
    Json peer;
    try {
        peer = Json::parse(line);
    } catch (const Json::exception&) {
        return {false, "peer_header_malformed", Json::object()};
    }
    if (peer.value("schema", 0) != 1 || peer.value("type", "") != "sample") {
        return {false, "peer_schema_mismatch", std::move(peer)};
    }
    if (peer.value("role", "") != expected_role) {
        return {false, "peer_role_mismatch", std::move(peer)};
    }
    for (const char* field : {"sample", "batch", "profile_hash"}) {
        if (!peer.contains(field) || peer.at(field) != header.at(field)) {
            return {false, std::string("peer_") + field + "_mismatch", std::move(peer)};
        }
    }
    if (!peer.contains("valid") || !peer.contains("pinned_cpu") || !peer.contains("capabilities") ||
        !peer.at("capabilities").is_object() || !peer.contains("declaration") ||
        !peer.at("declaration").is_object() || !peer.contains("config") ||
        !peer.at("config").is_object()) {
        return {false, "peer_metadata_incomplete", std::move(peer)};
    }
    return {true, "matched_opposite_role_header", std::move(peer)};
}

std::optional<std::string> director_invalid_reason(const std::filesystem::path& directory) {
    std::ifstream file(directory / "director.txt");
    if (!file) {
        return std::nullopt;
    }
    std::string line;
    if (!std::getline(file, line) || line != "valid") {
        return line.empty() ? "director status is empty" : line;
    }
    return std::nullopt;
}
std::optional<AuthoritativeLedger> authoritative_ledger(
    const std::filesystem::path& sample_path, const std::filesystem::path& input_root) {
    auto directory = sample_path.parent_path();
    const auto boundary = std::filesystem::is_regular_file(input_root)
                              ? input_root.parent_path()
                              : input_root;
    while (true) {
        const auto path = directory / "attempts.jsonl";
        std::error_code status_error;
        const auto status = std::filesystem::symlink_status(path, status_error);
        if (status_error && status_error != std::errc::no_such_file_or_directory)
            throw std::runtime_error("cannot inspect authoritative attempt ledger: " +
                                     path.string());
        if (status.type() != std::filesystem::file_type::not_found)
            return read_authoritative_ledger(path);
        if (directory == boundary || directory == directory.root_path())
            break;
        directory = directory.parent_path();
    }
    return std::nullopt;
}
double weighted(const std::vector<double>& sorted, unsigned first, unsigned last) {
    long double sum = 0;
    const auto n = sorted.size();
    for (std::size_t i = 0; i < n; ++i) {
        const auto begin = std::max(8 * i, first * n), end = std::min(8 * (i + 1), last * n);
        if (end > begin)
            sum += static_cast<long double>(sorted[i]) * (end - begin);
    }
    return static_cast<double>(sum / ((last - first) * n));
}
Json distribution(const std::vector<double>& values) {
    const auto s = statistics(values);
    return {{"count", s.count}, {"minimum", s.minimum}, {"maximum", s.maximum}, {"stq1", s.stq[0]},
            {"stq2", s.stq[1]}, {"stq3", s.stq[2]},     {"values", values}};
}
void svg(const std::filesystem::path& path, const std::vector<double>& values) {
    auto sorted = values;
    std::sort(sorted.begin(), sorted.end());
    const auto low = sorted.front(), high = sorted.back();
    std::ofstream out(path);
    out.exceptions(std::ios::badbit | std::ios::failbit);
    out << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"640\" height=\"320\">"
           "<rect width=\"640\" height=\"320\" fill=\"white\"/>"
           "<text x=\"40\" y=\"20\">Empirical cumulative distribution (raw ns)</text>"
           "<path d=\"M40 40V280H620\" fill=\"none\" stroke=\"black\"/>"
           "<polyline fill=\"none\" stroke=\"#164b87\" points=\"";
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        const double x = high > low ? 40 + 580 * (sorted[i] - low) / (high - low) : 330;
        out << x << ',' << 280 - 240 * static_cast<double>(i + 1) / sorted.size() << ' ';
    }
    out << "\"/><text x=\"40\" y=\"305\">" << low << " ns</text>"
        << "<text x=\"500\" y=\"305\">" << high << " ns</text></svg>\n";
}
} // namespace
Statistics statistics(std::span<const double> values) {
    if (values.empty())
        throw std::invalid_argument("statistics require samples");
    std::vector<double> sorted(values.begin(), values.end());
    for (double v : sorted)
        if (!std::isfinite(v))
            throw std::invalid_argument("nonfinite sample");
    std::sort(sorted.begin(), sorted.end());
    return {sorted.size(),
            sorted.front(),
            sorted.back(),
            {weighted(sorted, 1, 3), weighted(sorted, 3, 5), weighted(sorted, 5, 7)}};
}
Comparison compare(std::span<const double> a, std::span<const double> b, std::uint64_t seed,
                   std::size_t repetitions) {
    if (a.empty() || b.empty() || repetitions < 2)
        throw std::invalid_argument("bootstrap needs samples");
    const double difference = statistics(b).stq[1] - statistics(a).stq[1];
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<std::size_t> da(0, a.size() - 1), db(0, b.size() - 1);
    std::vector<double> aa(a.size()), bb(b.size()), differences;
    differences.reserve(repetitions);
    for (std::size_t i = 0; i < repetitions; ++i) {
        for (auto& v : aa)
            v = a[da(rng)];
        for (auto& v : bb)
            v = b[db(rng)];
        differences.push_back(statistics(bb).stq[1] - statistics(aa).stq[1]);
    }
    std::sort(differences.begin(), differences.end());
    const auto lo = differences[static_cast<std::size_t>(0.025 * (repetitions - 1))];
    const auto hi = differences[static_cast<std::size_t>(0.975 * (repetitions - 1))];
    return {difference, lo, hi, lo > 0 || hi < 0};
}
Json summarize(const std::filesystem::path& input, const std::filesystem::path& output) {
    std::vector<std::filesystem::path> paths;
    if (std::filesystem::is_regular_file(input))
        paths.push_back(input);
    else
        for (const auto& entry : std::filesystem::recursive_directory_iterator(input))
            if (entry.is_regular_file() && (entry.path().filename() == "client.jsonl" ||
                                            entry.path().filename() == "server.jsonl"))
                paths.push_back(entry.path());
    std::sort(paths.begin(), paths.end());
    Json samples = Json::array(), groups = Json::array();
    struct Group {
        Json dimensions;
        std::map<std::string, std::vector<double>> metrics;
        std::map<std::uint64_t, std::vector<double>> batches;
        std::set<std::string> comparison_exclusion_reasons;
        bool automatic_comparison_eligible = true;
    };
    std::map<std::string, Group> collected;
    std::size_t invalid = 0;
    bool saw_lookup_scenario = false;
    for (const auto& path : paths) {
        std::ifstream file(path);
        std::string line;
        if (!std::getline(file, line))
            throw std::runtime_error("empty raw record: " + path.string());
        auto header = Json::parse(line);
        if (header.at("type") != "sample" || header.at("schema") != 1)
            throw std::runtime_error("unsupported raw record schema");
        const auto scenario_name =
            header.at("config").value("scenario_name", std::string("standard-tls"));
        const bool lookup_scenario =
            scenario_name == "synthetic-lookup-plus-standard-tls" ||
            (header.at("config").contains("lookup") &&
             header.at("config").at("lookup").is_object() &&
             header.at("config").at("lookup").value("enabled", false));
        saw_lookup_scenario = saw_lookup_scenario || lookup_scenario;
        std::vector<Json> events;
        while (std::getline(file, line))
            if (!line.empty())
                events.push_back(Json::parse(line));
        auto parts = partition(header, events);
        std::string sidecar_status = "absent";
        std::string sidecar_reason = "optional_sidecar_not_present";
        auto sidecar_path = path;
        sidecar_path.replace_extension(".decoded.json");
        if (std::filesystem::exists(sidecar_path)) {
            sidecar_status = "ignored";
            try {
                if (const auto decoded = read_json(sidecar_path, sidecar_reason)) {
                    if (const auto connections =
                            decoded_connections(header, *decoded, sidecar_reason)) {
                        std::map<std::size_t, Json> windows;
                        bool complete = true;
                        for (const auto& part : parts) {
                            if (header.at("role") != "client")
                                continue;
                            const auto index = part.at("connection").get<std::size_t>();
                            const auto window =
                                alternate_window(header, events, connections->at(index));
                            if (!window) {
                                complete = false;
                                break;
                            }
                            windows.emplace(index, *window);
                        }
                        if (complete) {
                            for (auto& part : parts) {
                                const auto index = part.at("connection").get<std::size_t>();
                                if (windows.contains(index)) {
                                    part["client_hello_to_finished_send"] = windows.at(index);
                                }
                            }
                            sidecar_status = "validated";
                            sidecar_reason = header.at("role") == "client"
                                                 ? "alternate_window_available"
                                                 : "matching_complete_sidecar";
                        } else {
                            sidecar_reason = "alternate_boundary_unavailable";
                        }
                    }
                }
            } catch (const Json::exception&) {
                sidecar_reason = "sidecar_shape_invalid";
            } catch (const std::out_of_range&) {
                sidecar_reason = "sidecar_connection_lookup_failed";
            }
        }
        const auto peer = peer_header(path, header);
        const auto director_reason = director_invalid_reason(path.parent_path());
        const auto ledger = authoritative_ledger(path, input);
        std::optional<std::string> parent_status;
        NetworkEvidence network;
        if (ledger) {
            const auto sample = header.at("sample").get<std::uint64_t>();
            parent_status = ledger->attempts.contains(sample)
                                ? std::optional<std::string>(ledger->attempts.at(sample).status)
                                : std::optional<std::string>("incomplete");
            std::vector<NetworkAttempt> attempts;
            attempts.reserve(ledger->attempts.size());
            for (const auto& [id, attempt] : ledger->attempts) {
                (void)id;
                attempts.push_back(attempt);
            }
            network = read_network_evidence(
                ledger->root,
                lookup_scenario ? NetworkTopology::lookup_4ns
                                : NetworkTopology::tls_3ns_or_legacy_4ns,
                attempts);
        }
        const bool network_handoff =
            header.at("config").contains("network_handoff") &&
            header.at("config").at("network_handoff").is_object();
        const bool network_required = network.present || network_handoff;
        if (!network_required) {
            network.integrity = {{"status", "not_applicable_loopback"},
                                 {"eligible", true},
                                 {"reasons", Json::array()}};
        } else if (!network.present) {
            network.integrity = {
                {"status", "failed"}, {"eligible", false},
                {"reasons", Json::array({"network_provenance_missing_or_unreadable"})}};
        }
        bool valid = header.value("valid", false);
        for (const auto& p : parts)
            valid = valid && p.value("valid", false);
        if (parts.empty())
            valid = false;
        if (director_reason)
            valid = false;
        if (parent_status && *parent_status != "success")
            valid = false;
        std::string invalid_reason = header.value("invalid_reason", "");
        if (director_reason)
            invalid_reason = *director_reason;
        if (parent_status && *parent_status != "success")
            invalid_reason = "parent attempt ledger status: " + *parent_status;
        samples.push_back({{"path", path.string()},
                           {"sample", header.at("sample")},
                           {"role", header.at("role")},
                           {"valid", valid},
                           {"invalid_reason", invalid_reason},
                           {"peer_header_status", peer.verified ? "verified" : "unverified"},
                           {"peer_header_reason", peer.reason},
                           {"decoded_sidecar_status", sidecar_status},
                           {"decoded_sidecar_reason", sidecar_reason},
                           {"network_integrity", network.integrity},
                           {"connections", parts}});
        if (!valid) {
            ++invalid;
            continue;
        }
        const auto own_context = context_identity(header);
        const auto own_measurement_contract = measurement_contract_revision(header);
        const auto peer_measurement_contract =
            peer.verified ? measurement_contract_revision(peer.header) : Json(nullptr);
        Json dimensions = {
            {"role", header.at("role")},
            {"profile_hash", header.at("profile_hash")},
            {"environment_hash", header.at("environment_hash")},
            {"mode", header.at("mode")},
            {"observation_level", header.value("observation_level", "L0")},
            {"warmups", header.at("config").value("warmups", 0)},
            {"loaded_context", own_context.at("size").is_null()
                                   ? Json(nullptr)
                                   : Json(own_context.at("size").get<std::size_t>() > 0)},
            {"context_identity", own_context},
            {"peer_context_identity", peer.verified ? context_identity(peer.header) : Json(nullptr)},
            {"socket_settings", socket_settings(header)},
            {"peer_socket_settings", peer.verified ? socket_settings(peer.header) : Json(nullptr)},
            {"library", header.at("declaration").value("library", "")},
            {"library_version", header.at("declaration").value("version", "")},
            {"build_options", header.at("declaration").value("build_options", "")},
            {"measurement_contract_revision", own_measurement_contract},
            {"run_controls", Json::object()},
            {"client_adapter", header.at("config").value("client_adapter", "")},
            {"server_adapter", header.at("config").value("server_adapter", "")},
            {"pinned_cpu", header.value("pinned_cpu", -1)},
            {"peer_verified", peer.verified},
            {"peer_valid", peer.verified ? peer.header.value("valid", false) : false},
            {"peer_pinned_cpu", peer.verified ? peer.header.value("pinned_cpu", -1) : -1},
            {"peer_adapter",
             peer.verified
                 ? peer.header.at("config").value(
                       header.at("role") == "client" ? "server_adapter" : "client_adapter", "")
                 : ""},
            {"peer_library",
             peer.verified ? peer.header.at("declaration").value("library", "") : ""},
            {"peer_library_version",
             peer.verified ? peer.header.at("declaration").value("version", "") : ""},
            {"peer_build_options",
             peer.verified ? peer.header.at("declaration").value("build_options", "") : ""},
            {"peer_measurement_contract_revision", peer_measurement_contract},
            {"peer_capabilities",
             peer.verified ? peer.header.value("capabilities", Json::object()) : Json::object()},
            {"is_mock", header.at("declaration").value("is_mock", false)},
            {"correction", "raw"},
            {"timing_interpretation",
             header.at("mode") == "timing" ? "performance" : "diagnostic_only"}};
        dimensions["scenario_name"] = scenario_name;
        dimensions["lookup_requested_identity"] =
            lookup_scenario ? header.at("config").value("lookup", Json(nullptr)) : Json(nullptr);
        dimensions["network_requested_identity"] = nullptr;
        if (network_handoff)
            dimensions["network_requested_identity"] =
                header.at("config").at("network_handoff").value("net_profile", Json(nullptr));
        dimensions["network_actual_identity"] = network.condition_identity;
        // Lookup-specific cache/object identity remains in lookup-summary.json. Generic TLS
        // comparisons additionally require complete network evidence when a runner was used.
        dimensions["automatic_comparison_identity_complete"] =
            !lookup_scenario && (!network_required || network.condition_identity.is_object()) &&
            !own_measurement_contract.is_null() && !peer_measurement_contract.is_null();
        dimensions["run_controls"]["channel_observer"] = channel_observer_enabled(header);
        for (const char* control :
             {"perf", "kernel_timestamps", "isolate", "pin_cores", "tcp_nodelay",
              "socket_send_buffer", "socket_receive_buffer", "event_capacity", "stream_capacity",
              "keylog_capacity", "calibration_samples", "connections"})
            if (header.at("config").contains(control))
                dimensions["run_controls"][control] = header.at("config").at(control);
        for (const auto& p : parts) {
            // Positions share a process/context; never pool them as independent samples.
            dimensions["connection"] = p.at("connection");
            auto& group = collected[dimensions.dump()];
            group.dimensions = dimensions;
            if (own_measurement_contract.is_null())
                group.comparison_exclusion_reasons.insert(
                    "measurement_contract_revision_unknown");
            if (peer_measurement_contract.is_null())
                group.comparison_exclusion_reasons.insert(
                    "peer_measurement_contract_revision_unknown");
            const bool metrics_admitted =
                !network_required || network.integrity.value("eligible", false);
            group.automatic_comparison_eligible =
                group.automatic_comparison_eligible && metrics_admitted &&
                !own_measurement_contract.is_null() && !peer_measurement_contract.is_null();
            const bool primary_available =
                p.contains("primary_window") && p.at("primary_window").is_object() &&
                p.at("primary_window").value("available", false) && p.contains("elapsed_ns") &&
                !p.at("elapsed_ns").is_null();
            group.automatic_comparison_eligible =
                group.automatic_comparison_eligible && primary_available &&
                !native_stream_unobserved(header) && channel_observer_enabled(header);
            if (!metrics_admitted)
                continue;
            for (const auto* metric :
                 {"elapsed_ns", "computation_ns", "io_ns", "wait_ns", "gap_ns", "thread_cpu_ns",
                  "cycles", "instructions", "heap_peak_bytes"})
                if (p.contains(metric) && !p.at(metric).is_null())
                    group.metrics[metric].push_back(p.at(metric).get<double>());
            if (p.contains("client_hello_to_finished_send")) {
                const auto& window = p.at("client_hello_to_finished_send");
                group.metrics[std::string(alternate_elapsed)].push_back(
                    window.at("elapsed_ns").get<double>());
                if (!window.at("thread_cpu_ns").is_null()) {
                    group.metrics[std::string(alternate_thread_cpu)].push_back(
                        window.at("thread_cpu_ns").get<double>());
                }
                if (!window.at("cycles").is_null()) {
                    group.metrics[std::string(alternate_cycles)].push_back(
                        window.at("cycles").get<double>());
                }
            }
            if (p.contains(std::string(common_window_name))) {
                const auto& window = p.at(std::string(common_window_name));
                if (window.value("available", false) && !window.at("elapsed_ns").is_null())
                    group.metrics[std::string(common_elapsed)].push_back(
                        window.at("elapsed_ns").get<double>());
                if (window.value("available", false) &&
                    !window.at("thread_cpu_ns").is_null())
                    group.metrics[std::string(common_thread_cpu)].push_back(
                        window.at("thread_cpu_ns").get<double>());
            }
            if (primary_available)
                group.batches[header.at("batch").get<std::uint64_t>()].push_back(
                    p.at("elapsed_ns").get<double>());
        }
    }
    std::filesystem::create_directories(output);
    std::size_t group_index = 0;
    for (const auto& [key, group] : collected) {
        (void)key;
        Json item = {{"dimensions", group.dimensions},
                     {"metrics", Json::object()},
                     {"batches", Json::array()},
                     {"comparison_exclusion_reasons", group.comparison_exclusion_reasons},
                     {"automatic_comparison_eligible",
                      group.automatic_comparison_eligible}};
        for (const auto& [name, values] : group.metrics)
            item["metrics"][name] = distribution(values);
        if (group.metrics.contains(std::string(alternate_elapsed))) {
            item["client_hello_to_finished_send"] = {
                {"mapping", "record_envelope_overlap"},
                {"separate_plaintext_message_cpu_time_available", false},
                {"limitation",
                 "A TLS record or I/O return may contain multiple plaintext messages."},
            };
        }
        if (group.metrics.contains(std::string(common_elapsed))) {
            item[std::string(common_window_name)] = {
                {"definition", common_window_name},
                {"start", "first_handshake_call_begin"},
                {"end",
                 "last_successful_full_application_completion_call_end_for_role"},
                {"client_end_call", "app_recv"},
                {"server_end_call", "app_send"},
            };
        }
        std::vector<double> batch_stq;
        item["batch_ids"] = Json::array();
        for (const auto& [batch, values] : group.batches) {
            auto d = distribution(values);
            d["batch"] = batch;
            item["batches"].push_back(d);
            item["batch_ids"].push_back(batch);
            batch_stq.push_back(d["stq2"].get<double>());
        }
        item["batch_stq2_range_ns"] = batch_stq.empty()
                                          ? Json(nullptr)
                                          : Json(*std::max_element(batch_stq.begin(), batch_stq.end()) -
                                                 *std::min_element(batch_stq.begin(), batch_stq.end()));
        if (group.metrics.contains("elapsed_ns")) {
            const auto filename = "distribution-" + std::to_string(group_index++) + ".svg";
            svg(output / filename, group.metrics.at("elapsed_ns"));
            item["distribution_svg"] = filename;
        } else {
            item["distribution_svg"] = nullptr;
        }
        groups.push_back(item);
    }
    Json comparisons = Json::array();
    for (std::size_t a = 0; a < groups.size(); ++a)
        for (std::size_t b = a + 1; b < groups.size(); ++b) {
            auto da = groups[a]["dimensions"], db = groups[b]["dimensions"];
            if (da["mode"] != "timing" || db["mode"] != "timing")
                continue;
            if (!groups[a].value("automatic_comparison_eligible", false) ||
                !groups[b].value("automatic_comparison_eligible", false))
                continue;
            if (!da.value("automatic_comparison_identity_complete", false) ||
                !db.value("automatic_comparison_identity_complete", false))
                continue;
            if (!da.value("peer_verified", false) || !db.value("peer_verified", false) ||
                !da.value("peer_valid", false) || !db.value("peer_valid", false))
                continue;
            if (!observed_sockets(da["socket_settings"]) ||
                !observed_sockets(db["socket_settings"]) ||
                !observed_sockets(da["peer_socket_settings"]) ||
                !observed_sockets(db["peer_socket_settings"]))
                continue;
            if (da["context_identity"]["hash"].is_null() ||
                db["context_identity"]["hash"].is_null() ||
                da["peer_context_identity"]["hash"].is_null() ||
                db["peer_context_identity"]["hash"].is_null())
                continue;
            if (groups[a]["batch_ids"] != groups[b]["batch_ids"])
                continue;
            if (!groups[a]["metrics"].contains("elapsed_ns") ||
                !groups[b]["metrics"].contains("elapsed_ns"))
                continue;
            const auto role = da.at("role").get<std::string>();
            const char* own_adapter = role == "client" ? "client_adapter" : "server_adapter";
            for (const char* field : {own_adapter, "library", "library_version", "build_options"}) {
                da.erase(field);
                db.erase(field);
            }
            if (da != db)
                continue;
            const auto av = groups[a]["metrics"]["elapsed_ns"]["values"].get<std::vector<double>>();
            const auto bv = groups[b]["metrics"]["elapsed_ns"]["values"].get<std::vector<double>>();
            const auto c = compare(av, bv);
            const auto batch_range = std::max(groups[a]["batch_stq2_range_ns"].get<double>(),
                                              groups[b]["batch_stq2_range_ns"].get<double>());
            comparisons.push_back(
                {{"group_a", a},
                 {"group_b", b},
                 {"difference_b_minus_a_ns", c.difference},
                 {"lower_95_ns", c.lower},
                 {"upper_95_ns", c.upper},
                 {"distinguishable", c.distinguishable},
                 {"method", "independent_percentile_bootstrap"},
                 {"interpretation", "exploratory_adapter_candidate_not_equivalence"},
                 {"eligibility",
                  "same_conditions_verified_fixed_peer_and_batch_ids_except_measured_adapter_"
                  "identity"},
                 {"seed", 1},
                 {"replicates", 2000},
                 {"batch_variation_warning", batch_range > std::abs(c.difference)}});
        }
    Json result = {{"schema", 1},
                   {"comparisons", comparisons},
                   {"groups", groups},
                   {"samples", samples},
                   {"invalid_samples", invalid},
                   {"notes",
                    {"Endpoint roles are never added together.",
                     "Kernel timestamps are excluded from L0 partitions.",
                     "Raw boundary times; no calibration subtraction is applied.",
                     "Missing or multiplexed counters are not synthesized."}}};
    bool has_lookup_artifacts = false;
    if (!std::filesystem::is_regular_file(input)) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(input)) {
            if (entry.is_regular_file() &&
                (entry.path().filename() == "lookup.jsonl" ||
                 entry.path().filename() == "ca.jsonl")) {
                has_lookup_artifacts = true;
                break;
            }
        }
    }
    if (saw_lookup_scenario || has_lookup_artifacts) {
        (void)summarize_lookup(input, output);
        result["lookup_summary"] = {{"path", "lookup-summary.json"},
                                    {"type", "turtle-lookup-summary"},
                                    {"schema", 1}};
    }
    std::ofstream out(output / "summary.json");
    out.exceptions(std::ios::badbit | std::ios::failbit);
    out << result.dump(2) << '\n';
    return result;
}
} // namespace turtle::report
