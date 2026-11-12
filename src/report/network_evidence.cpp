#include "report/network_evidence.hpp"

#include <algorithm>
#include <fstream>
#include <set>
#include <stdexcept>
#include <string_view>

namespace turtle::report {
namespace {
using Json = nlohmann::json;

Json read_json(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input)
        return nullptr;
    try {
        Json value;
        input >> value;
        return value;
    } catch (const Json::exception&) {
        return nullptr;
    }
}

bool volatile_identity_key(std::string_view key) {
    static constexpr std::string_view exact[] = {"pid",          "pids",          "fd",
                                                 "fds",          "path",          "port",
                                                 "ports",        "handle",        "timestamp",
                                                 "monotonic_ns", "namespace_pid", "namespace_inode",
                                                 "time",         "started_at",    "ended_at",
                                                 "drops",        "drop",          "actual_drop",
                                                 "retrans",      "retransmits",   "total_retrans",
                                                 "outcome",      "status",        "reason"};
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
    for (auto it = value.begin(); it != value.end(); ++it)
        if (!volatile_identity_key(it.key()))
            output[it.key()] = stable_identity(it.value());
    return output;
}

bool observed_true(const Json& object, std::string_view field) {
    return object.is_object() && object.contains(std::string(field)) &&
           object.at(std::string(field)).is_boolean() && object.at(std::string(field)).get<bool>();
}

std::set<std::string> keys(const Json& object) {
    std::set<std::string> result;
    if (object.is_object())
        for (auto it = object.begin(); it != object.end(); ++it)
            result.insert(it.key());
    return result;
}

struct ExpectedTopology {
    std::string_view kind;
    Json addresses;
    Json interfaces;
    std::set<std::string> paths;
    std::set<std::string> helpers;
};

ExpectedTopology expected(NetworkTopology topology) {
    if (topology != NetworkTopology::lookup_4ns) {
        return {"three-netns-receiver-facing-router-egress",
                {{"client_tls", "10.203.1.2"}, {"server", "10.203.2.2"}},
                {{"client_tls", "ctls"},
                 {"server", "stls"},
                 {"router_client_tls", "rctls"},
                 {"router_server", "rstls"}},
                {"tls_c2s", "tls_s2c"},
                {"client", "server", "router"}};
    }
    return {"four-netns-receiver-facing-router-egress",
            {{"client_tls", "10.203.1.2"},
             {"server", "10.203.2.2"},
             {"client_ca", "10.203.3.2"},
             {"ca", "10.203.4.2"}},
            {{"client_tls", "ctls"},
             {"server", "stls"},
             {"client_ca", "cca"},
             {"ca", "ca0"},
             {"router_client_tls", "rctls"},
             {"router_server", "rstls"},
             {"router_client_ca", "rcca"},
             {"router_ca", "rca0"}},
            {"tls_c2s", "tls_s2c", "ca_c2s", "ca_s2c"},
            {"client", "server", "ca", "router"}};
}

void validate_topology(const Json& provenance, NetworkTopology topology, Json& reasons) {
    const auto contract = expected(topology);
    const auto condition = provenance.value("condition_identity", Json::object());
    const auto declared = condition.value("topology", Json::object());
    if (!declared.is_object() || declared.value("kind", "") != contract.kind ||
        declared.value("addresses", Json(nullptr)) != contract.addresses ||
        declared.value("interfaces", Json(nullptr)) != contract.interfaces)
        reasons.push_back("network_topology_identity_mismatch");

    const auto actual = condition.value("actual", Json::object());
    if (!actual.is_object() || keys(actual.value("paths", Json(nullptr))) != contract.paths)
        reasons.push_back("active_network_path_inventory_mismatch");
    if (keys(provenance.value("applied_qdisc_readback", Json(nullptr))) != contract.paths)
        reasons.push_back("qdisc_readback_inventory_mismatch");
    const auto requested_paths =
        condition.value("requested", Json::object()).value("paths", Json::object());
    const auto actual_paths = actual.value("paths", Json::object());
    const auto requested_qdisc = condition.value("requested", Json::object()).value("qdisc", "");
    const auto actual_qdisc = actual.value("qdisc", "");
    const auto readbacks = provenance.value("applied_qdisc_readback", Json::object());
    const auto expected_interface = [](std::string_view path) -> std::string_view {
        if (path == "tls_c2s")
            return "rstls";
        if (path == "tls_s2c")
            return "rctls";
        if (path == "ca_c2s")
            return "rca0";
        return "rcca";
    };
    for (const auto& path : contract.paths) {
        if (!requested_paths.contains(path) || !requested_paths.at(path).is_object()) {
            reasons.push_back("requested_network_path_missing:" + path);
        } else {
            const auto& value = requested_paths.at(path);
            for (const char* field : {"delay_ms", "loss_percent", "limit_packets"})
                if (!value.contains(field) || !value.at(field).is_number())
                    reasons.push_back("requested_network_path_field_missing:" + path + ":" + field);
        }
        if (!actual_paths.contains(path) || !actual_paths.at(path).is_object()) {
            reasons.push_back("actual_network_path_missing:" + path);
        } else {
            const auto& value = actual_paths.at(path);
            for (const char* field : {"delay_ms", "loss_percent"})
                if (!value.contains(field) || !value.at(field).is_number())
                    reasons.push_back("actual_network_path_field_missing:" + path + ":" + field);
            const bool noqueue_limit_not_applicable =
                requested_qdisc == "none" && actual_qdisc == "none" &&
                value.value("kind", "") == "noqueue" && value.contains("limit_packets") &&
                value.at("limit_packets").is_null();
            if (!value.contains("limit_packets") ||
                (!value.at("limit_packets").is_number() && !noqueue_limit_not_applicable))
                reasons.push_back("actual_network_path_field_missing:" + path + ":limit_packets");
        }
        if (!readbacks.contains(path) || !readbacks.at(path).is_object() ||
            readbacks.at(path).value("interface", "") != expected_interface(path))
            reasons.push_back("qdisc_readback_interface_mismatch:" + path);
    }

    const auto mtu = condition.value("mtu", Json::object());
    const auto offload = condition.contains("offload")
                             ? condition.at("offload")
                             : condition.value("offloads", Json::object());
    if (!mtu.is_object() || !mtu.contains("requested") || !mtu.contains("actual") ||
        mtu.at("requested").is_null() || !mtu.at("actual").is_object() || mtu.at("actual").empty())
        reasons.push_back("mtu_requested_or_actual_identity_missing");
    if (!offload.is_object() || !offload.contains("requested") || !offload.contains("actual") ||
        offload.at("requested").is_null() || !offload.at("actual").is_object() ||
        offload.at("actual").empty())
        reasons.push_back("offload_requested_or_actual_identity_missing");
    if (!condition.contains("requested") || condition.at("requested").is_null() ||
        !condition.contains("actual") || condition.at("actual").is_null())
        reasons.push_back("network_requested_or_actual_identity_missing");
}

Json read_observations(const std::filesystem::path& path) {
    Json observations = Json::object();
    std::ifstream input(path);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty())
            continue;
        try {
            const auto row = Json::parse(line);
            if (row.value("type", "") != "network-observation" || row.value("schema", 0) != 1 ||
                !row.contains("observation_id") || !row.at("observation_id").is_string() ||
                !row.contains("attempt") || !row.at("attempt").is_number_unsigned() ||
                (row.value("phase", "") != "setup" && row.value("phase", "") != "scenario" &&
                 row.value("phase", "") != "cleanup") ||
                (row.value("edge", "") != "begin" && row.value("edge", "") != "end"))
                continue;
            const auto canonical = std::to_string(row.at("attempt").get<std::uint64_t>()) + ":" +
                                   row.at("phase").get<std::string>() + ":" +
                                   row.at("edge").get<std::string>();
            const auto id = row.at("observation_id").get<std::string>();
            const bool partial =
                row.value("record_kind", "") == "partial-window" && id.starts_with(canonical + ":");
            if ((id != canonical && !partial) || observations.contains(id))
                continue;
            observations[id] = row;
        } catch (const Json::exception&) {
        }
    }
    return observations;
}

} // namespace

AuthoritativeLedger read_authoritative_ledger(const std::filesystem::path& path) {
    if (!std::filesystem::is_regular_file(path))
        throw std::runtime_error("authoritative attempt ledger is not a regular file: " +
                                 path.string());
    std::ifstream file(path);
    if (!file)
        throw std::runtime_error("authoritative attempt ledger is unreadable: " + path.string());

    AuthoritativeLedger ledger;
    ledger.root = path.parent_path();
    std::set<std::uint64_t> finalized;
    std::string line;
    bool header_seen = false;
    while (std::getline(file, line)) {
        if (line.empty())
            continue;
        Json row;
        try {
            row = Json::parse(line);
        } catch (const Json::parse_error&) {
            bool later_nonempty = false;
            std::string remainder;
            while (std::getline(file, remainder))
                later_nonempty = later_nonempty || !remainder.empty();
            bool outstanding_attempt = false;
            for (const auto& [id, attempt] : ledger.attempts)
                outstanding_attempt =
                    outstanding_attempt || (attempt.started && !finalized.contains(id));
            if (!header_seen || later_nonempty || !ledger.run_summary.is_null() ||
                !outstanding_attempt)
                throw std::runtime_error("authoritative attempt ledger contains malformed JSON: " +
                                         path.string());
            ledger.partial = true;
            break;
        }

        if (!row.is_object() || !row.contains("type") || !row.at("type").is_string() ||
            row.at("type") != "turtle-attempt-ledger" || !row.contains("schema") ||
            !row.at("schema").is_number_integer() || row.at("schema") != 1 ||
            !row.contains("record_kind") || !row.at("record_kind").is_string())
            throw std::runtime_error(std::string("authoritative attempt ledger has invalid ") +
                                     (header_seen ? "row: " : "run_config: ") + path.string());

        const auto kind = row.at("record_kind").get<std::string>();
        if (!header_seen) {
            if (kind != "run_config" || !row.contains("requested_count") ||
                !row.at("requested_count").is_number_unsigned())
                throw std::runtime_error("authoritative attempt ledger has invalid run_config: " +
                                         path.string());
            ledger.requested = row.at("requested_count").get<std::size_t>();
            if (ledger.requested == 0)
                throw std::runtime_error("authoritative attempt ledger requested_count is zero: " +
                                         path.string());
            header_seen = true;
            ledger.rows.push_back(std::move(row));
            continue;
        }

        if (kind == "run_summary") {
            if (!ledger.run_summary.is_null() || row.contains("attempt_id"))
                throw std::runtime_error("authoritative attempt ledger has invalid run_summary: " +
                                         path.string());
            for (const char* field : {"requested", "started", "success", "timeout", "error",
                                      "incomplete", "not_attempted", "missing_artifacts"})
                if (!row.contains(field) || !row.at(field).is_number_unsigned())
                    throw std::runtime_error(
                        "authoritative attempt ledger has invalid run_summary: " + path.string());
            if (!row.contains("missing_artifact_rows") ||
                !row.at("missing_artifact_rows").is_array())
                throw std::runtime_error("authoritative attempt ledger has invalid run_summary: " +
                                         path.string());
            const auto requested = row.at("requested").get<std::size_t>();
            const auto started = row.at("started").get<std::size_t>();
            const auto terminal =
                row.at("success").get<std::size_t>() + row.at("timeout").get<std::size_t>() +
                row.at("error").get<std::size_t>() + row.at("incomplete").get<std::size_t>();
            if (requested != ledger.requested ||
                started + row.at("not_attempted").get<std::size_t>() != requested ||
                terminal != started)
                throw std::runtime_error(
                    "authoritative attempt ledger run_summary denominator mismatch: " +
                    path.string());
            ledger.run_summary = row;
            ledger.rows.push_back(std::move(row));
            continue;
        }
        if (!ledger.run_summary.is_null())
            throw std::runtime_error("authoritative attempt ledger has rows after run_summary: " +
                                     path.string());
        if (kind != "attempt_started" && kind != "attempt_final")
            throw std::runtime_error("authoritative attempt ledger record kind is invalid: " +
                                     path.string());
        if (!row.contains("attempt_id") || !row.at("attempt_id").is_number_unsigned())
            throw std::runtime_error("authoritative attempt ledger has invalid row: " +
                                     path.string());
        const auto id = row.at("attempt_id").get<std::uint64_t>();
        if (id == 0 || id > ledger.requested)
            throw std::runtime_error("authoritative attempt ledger attempt id is out of range: " +
                                     path.string());
        auto& attempt = ledger.attempts[id];
        attempt.id = id;
        if (kind == "attempt_started") {
            attempt.started = true;
            attempt.status = "incomplete";
        } else {
            if (!finalized.insert(id).second)
                throw std::runtime_error("authoritative attempt ledger has duplicate final row: " +
                                         path.string());
            attempt.started = true;
            if (!row.contains("final_status") || !row.at("final_status").is_string())
                throw std::runtime_error("authoritative attempt ledger final status is invalid: " +
                                         path.string());
            attempt.status = row.at("final_status").get<std::string>();
            if (attempt.status != "success" && attempt.status != "timeout" &&
                attempt.status != "error" && attempt.status != "incomplete")
                throw std::runtime_error("authoritative attempt ledger final status is invalid: " +
                                         path.string());
            attempt.observation_ids = row.value("network_observation_ids", Json::array());
            if (!attempt.observation_ids.is_array())
                throw std::runtime_error(
                    "authoritative attempt ledger observation references are invalid: " +
                    path.string());
        }
        ledger.rows.push_back(std::move(row));
    }

    if (!header_seen)
        throw std::runtime_error("authoritative attempt ledger has no valid run_config: " +
                                 path.string());
    for (std::uint64_t id = 1; id <= ledger.requested; ++id)
        if (!ledger.attempts.contains(id))
            ledger.attempts.emplace(id, NetworkAttempt{id, false, "not_attempted", Json::array()});

    if (ledger.run_summary.is_null() && !ledger.partial)
        throw std::runtime_error("authoritative attempt ledger is missing run_summary: " +
                                 path.string());
    if (!ledger.run_summary.is_null()) {
        std::size_t started = 0, success = 0, timeout = 0, error = 0, incomplete = 0;
        for (const auto& [id, attempt] : ledger.attempts) {
            (void)id;
            if (!attempt.started)
                continue;
            ++started;
            success += attempt.status == "success";
            timeout += attempt.status == "timeout";
            error += attempt.status == "error";
            incomplete += attempt.status == "incomplete";
        }
        if (ledger.run_summary.at("started") != started ||
            ledger.run_summary.at("success") != success ||
            ledger.run_summary.at("timeout") != timeout ||
            ledger.run_summary.at("error") != error ||
            ledger.run_summary.at("incomplete") != incomplete)
            throw std::runtime_error(
                "authoritative attempt ledger run_summary disagrees with attempt rows: " +
                path.string());
    }
    return ledger;
}

NetworkEvidence read_network_evidence(const std::filesystem::path& root,
                                      NetworkTopology expected_topology,
                                      const std::vector<NetworkAttempt>& attempts) {
    const auto provenance = read_json(root / "network-provenance.json");
    NetworkEvidence evidence;
    evidence.present = provenance.is_object();
    evidence.observations = read_observations(root / "network-observations.jsonl");
    Json reasons = Json::array();
    if (!evidence.present) {
        evidence.integrity = {
            {"status", "not_observed"},
            {"eligible", false},
            {"reasons", Json::array({"network_provenance_missing_or_unreadable"})}};
        return evidence;
    }
    if (provenance.value("type", "") != "turtle-network-provenance" ||
        provenance.value("schema", 0) != 2)
        reasons.push_back("network_provenance_schema_invalid");
    evidence.condition_identity = provenance.contains("condition_identity")
                                      ? stable_identity(provenance.at("condition_identity"))
                                      : Json(nullptr);
    validate_topology(provenance, expected_topology, reasons);
    const bool kernel_requested = provenance.value("condition_identity", Json::object())
                                      .value("requested", Json::object())
                                      .value("kernel_events", false);
    if (kernel_requested) {
        const auto kernel = read_json(root / "kernel-events.json");
        bool complete = kernel.is_object() && kernel.value("type", "") == "turtle-kernel-events" &&
                        kernel.value("schema", 0) == 1 &&
                        kernel.value("status", "") == "complete" &&
                        kernel.value("buffer_lost", -1) == 0 &&
                        kernel.value("cleanup_errors", Json(nullptr)) == Json::array() &&
                        kernel.value("targeted_loss_complete", false);
        const auto failures =
            kernel.is_object() ? kernel.value("failures", Json(nullptr)) : Json(nullptr);
        complete = complete && failures.is_object() && !failures.empty();
        if (failures.is_object())
            for (const auto& value : failures)
                complete = complete && value.is_number_integer() && value == 0;
        if (!complete)
            reasons.push_back("requested_kernel_collection_or_targeted_loss_incomplete");
    }

    const auto status = provenance.value("status", "");
    const auto returncode = provenance.value("runner", Json::object()).value("returncode", -999);
    const auto trace =
        provenance.value("condition_identity", Json::object()).value("trace", Json::object());
    const bool trace_known = trace.contains("requested") && trace.at("requested").is_boolean();
    const bool trace_requested = trace_known && trace.at("requested").get<bool>();
    bool expected_failure = false;
    bool complete_denominator = !attempts.empty();
    bool all_success = !attempts.empty();
    bool success_or_timeout = !attempts.empty();
    bool saw_timeout = false;
    for (const auto& attempt : attempts) {
        complete_denominator = complete_denominator && attempt.started;
        all_success = all_success && attempt.started && attempt.status == "success";
        success_or_timeout = success_or_timeout && attempt.started &&
                             (attempt.status == "success" || attempt.status == "timeout");
        saw_timeout = saw_timeout || (attempt.started && attempt.status == "timeout");
        if (attempt.status != "success")
            continue;
        std::set<std::string> required;
        for (const char* phase : {"setup", "scenario", "cleanup"})
            for (const char* edge : {"begin", "end"})
                required.insert(std::to_string(attempt.id) + ":" + phase + ":" + edge);
        std::set<std::string> referenced;
        if (attempt.observation_ids.is_array())
            for (const auto& id : attempt.observation_ids)
                if (id.is_string())
                    referenced.insert(id.get<std::string>());
        if (referenced != required || attempt.observation_ids.size() != required.size())
            reasons.push_back("successful_attempt_requires_exact_six_phase_observations");
        for (const auto& id : required) {
            if (!evidence.observations.contains(id)) {
                reasons.push_back("referenced_network_observation_missing:" + id);
                continue;
            }
            const auto& observation = evidence.observations.at(id);
            const bool qdiscs_complete = observation.contains("qdiscs") &&
                                         observation.at("qdiscs").is_object() &&
                                         !observation.at("qdiscs").empty();
            const bool trace_complete =
                !trace_requested ||
                (observation.contains("packet_trace") && !observation.at("packet_trace").is_null());
            if (!qdiscs_complete || !trace_complete)
                reasons.push_back("referenced_network_observation_payload_incomplete:" + id);
        }
    }
    if (status == "complete" && returncode == 0) {
        if (!complete_denominator || !all_success)
            reasons.push_back("successful_runner_lacks_complete_success_denominator");
    } else if (status == "runner-failed" && returncode == 1) {
        expected_failure = complete_denominator && success_or_timeout && saw_timeout;
        if (!expected_failure)
            reasons.push_back("runner_failure_lacks_expected_timeout_ledger_evidence");
    } else {
        reasons.push_back("network_runner_status_or_runner_outcome_invalid");
    }

    const auto host = provenance.value("host_network_identity", Json::object());
    if (!observed_true(host, "unchanged") ||
        !observed_true(host.value("before", Json::object()), "supported") ||
        !observed_true(host.value("after", Json::object()), "supported"))
        reasons.push_back("supported_unchanged_host_network_identity_not_proven");
    const auto lifecycle = provenance.value("lifecycle", Json::object());
    if (!lifecycle.value("namespace_fds_closed", false) ||
        !lifecycle.value("owned_pipe_fds_closed", false))
        reasons.push_back("owned_descriptor_cleanup_not_proven");
    if (provenance.contains("secondary_cleanup_failures") &&
        provenance.at("secondary_cleanup_failures").is_array() &&
        !provenance.at("secondary_cleanup_failures").empty())
        reasons.push_back("owned_cleanup_reported_secondary_failures");
    if (std::filesystem::exists(root / "network-cleanup-errors.json") ||
        std::filesystem::exists(root / "network-provenance.partial.json"))
        reasons.push_back("cleanup_or_provenance_sidecar_is_partial");

    std::set<std::string> helpers;
    bool observer_done = false, kernel_observer_done = false, fatal_not_reaped = false;
    for (const auto& item : provenance.value("cleanup", Json::array())) {
        if (!item.is_object())
            continue;
        if (item.contains("helper") && item.contains("result") &&
            (item.at("result") == "reaped" || item.at("result") == "killed"))
            helpers.insert(item.at("helper").get<std::string>());
        if (item.contains("observer") &&
            (item.at("observer") == "reaped" || item.at("observer") == "killed-after-500ms"))
            observer_done = true;
        if (item.value("kernel_observer", "") == "reaped" && item.value("returncode", -1) == 0 &&
            item.value("collection_complete", false))
            kernel_observer_done = true;
        for (auto it = item.begin(); it != item.end(); ++it)
            fatal_not_reaped = fatal_not_reaped || it.value() == "fatal-not-reaped";
    }
    if (fatal_not_reaped)
        reasons.push_back("owned_process_not_reaped");
    if (kernel_requested && !kernel_observer_done)
        reasons.push_back("owned_kernel_observer_cleanup_incomplete");
    if (!trace_known)
        reasons.push_back("trace_request_identity_missing");
    if (helpers != expected(expected_topology).helpers || (trace_requested && !observer_done) ||
        !provenance.contains("finished_monotonic_ns") ||
        provenance.at("finished_monotonic_ns").is_null())
        reasons.push_back("owned_helper_observer_cleanup_inventory_incomplete");

    evidence.integrity = {{"status", reasons.empty() ? "complete" : "failed"},
                          {"eligible", reasons.empty()},
                          {"expected_runner_failure", expected_failure},
                          {"trace_requested", trace_known ? Json(trace_requested) : Json(nullptr)},
                          {"kernel_events_requested", kernel_requested},
                          {"reasons", reasons}};
    return evidence;
}

} // namespace turtle::report
