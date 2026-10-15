#include "report/report.hpp"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

namespace {
using Json = nlohmann::json;

void line(std::ofstream& out, const Json& value) {
    out << value.dump() << '\n';
}

Json ledger_row(std::uint64_t attempt, std::string status, Json connections,
                Json observations = Json::array()) {
    return {{"type", "turtle-attempt-ledger"}, {"schema", 1},
            {"record_kind", "attempt_final"}, {"attempt_id", attempt},
            {"requested_count", 5}, {"started", true}, {"final_status", status},
            {"failure_phase", status == "timeout" ? "scenario" : "none"},
            {"reason", status == "success" ? "" : status + " fixture"},
            {"artifact_status", Json::array({"complete", "complete", "complete"})},
            {"artifacts", {{"server.jsonl", "complete"}, {"client.jsonl", "complete"},
                            {"lookup.jsonl", status == "incomplete" ? "partial" : "complete"},
                            {"ca.jsonl", status == "error" ? "missing" : "complete"}}},
            {"connections", connections}, {"network_observation_ids", observations}};
}

Json ledger_summary(std::size_t requested, std::size_t started, std::size_t success,
                    std::size_t timeout, std::size_t error, std::size_t incomplete) {
    return {{"type", "turtle-attempt-ledger"}, {"schema", 1},
            {"record_kind", "run_summary"}, {"requested", requested},
            {"started", started}, {"success", success}, {"timeout", timeout},
            {"error", error}, {"incomplete", incomplete},
            {"not_attempted", requested - started}, {"missing_artifacts", 0},
            {"missing_artifact_rows", Json::array()}};
}

Json tls_header(std::uint64_t sample, bool valid = true) {
    return {{"type", "sample"}, {"schema", 1}, {"sample", sample}, {"batch", 1},
            {"measurement_contract_revision", 1},
            {"role", "client"}, {"valid", valid}, {"profile_hash", "tls-profile"},
            {"environment_hash", "env"}, {"mode", "timing"}, {"pinned_cpu", 2},
            {"loaded_context_size", 0}, {"loaded_context_hash", ""},
            {"perf_complete", false},
            {"config", {{"scenario_name", "synthetic-lookup-plus-standard-tls"},
                         {"lookup", {{"enabled", true}, {"cache_mode", "empty"}}},
                         {"client_adapter", "fixture-client"}, {"server_adapter", "fixture-server"},
                         {"perf", false}, {"isolate", true}, {"pin_cores", true},
                         {"kernel_timestamps", false},
                         {"timeout_ms", 10000}, {"failure_policy", "fixed-attempts"},
                         {"flush_grace_ms", 500},
                         {"warmups", 0}, {"connections", 2}, {"tcp_nodelay", true},
                         {"socket_send_buffer", 1024}, {"socket_receive_buffer", 2048}}},
            {"declaration", {{"library", "fixture"}, {"version", "1"},
                              {"build_options", "default"}}},
            {"capabilities", {{"monotonic_clock", true}, {"thread_cpu_clock", true},
                               {"perf", false}, {"heap_tracking", true}, {"affinity", true},
                               {"kernel_timestamp_configured", false}}},
            {"observation_level", "L0"},
            {"connections", Json::array({{{"index", 0}, {"warmup", false},
                                            {"application_verified", true},
                                            {"socket", {{"nonblocking", true}, {"tcp_nodelay", true},
                                                        {"send_buffer", 1024}, {"receive_buffer", 2048},
                                                        {"kernel_timestamps", false}}},
                                            {"tcp_start", {{"snd_mss", 1448}, {"rcv_mss", 1448}}}},
                                          {{"index", 1}, {"warmup", false},
                                            {"application_verified", true},
                                            {"socket", {{"nonblocking", true}, {"tcp_nodelay", true},
                                                        {"send_buffer", 1024}, {"receive_buffer", 2048},
                                                        {"kernel_timestamps", false}}},
                                            {"tcp_start", {{"snd_mss", 1448}, {"rcv_mss", 1448}}}}})}};
}

void write_tls(const std::filesystem::path& directory, std::uint64_t sample) {
    std::ofstream out(directory / "client.jsonl");
    line(out, tls_header(sample));
    for (std::size_t connection = 0; connection < 2; ++connection) {
        const auto base = 1000 + connection * 100;
        line(out, {{"connection", connection}, {"location", "implementation_boundary"},
                   {"kind", "CALL_BEGIN"}, {"call", "handshake"},
                   {"monotonic_ns", base}});
        line(out, {{"connection", connection}, {"location", "implementation_boundary"},
                   {"kind", "CALL_END"}, {"call", "handshake"}, {"result", 0},
                   {"monotonic_ns", base + 20}});
        line(out, {{"connection", connection}, {"location", "implementation_boundary"},
                   {"kind", "CALL_BEGIN"}, {"call", "app_recv"},
                   {"monotonic_ns", base + 30}});
        line(out, {{"connection", connection}, {"location", "implementation_boundary"},
                   {"kind", "CALL_END"}, {"call", "app_recv"}, {"result", 2},
                   {"monotonic_ns", base + 50}});
    }
    auto server = tls_header(sample);
    server["role"] = "server";
    server["pinned_cpu"] = 3;
    std::ofstream(directory / "server.jsonl") << server.dump() << '\n';
}

Json service_header(std::string type, std::uint64_t sample, int cpu) {
    return {{"type", type}, {"schema", 1}, {"record_kind", "header"},
            {"sample", sample},
            {"scenario_name", "synthetic-lookup-plus-standard-tls"},
            {"cache_mode", "empty"}, {"cache_state_id", "empty:fixture"},
            {"object_id", "fnv1a64:0000000000001234"}, {"object_size", 123},
            {"initial_cache_bytes", 0},
            {"cache_capacity", 256}, {"reference_bytes", 123},
            {"reference_capacity", 256}, {"framework_reserved_bytes", 4096},
            {"mode", "timing"}, {"pinned_cpu", cpu}, {"observation_level", "L0"}};
}

void event(std::ofstream& out, std::string type, std::uint64_t sample, std::size_t connection,
           std::string kind, std::uint64_t monotonic, std::uint64_t cpu) {
    line(out, {{"type", type}, {"schema", 1}, {"record_kind", "event"},
               {"sample", sample}, {"connection", connection}, {"request_id", 1},
               {"sequence", monotonic}, {"participant", type == "mock-ca" ? "mock-ca" : "client"},
               {"stream_id", "fixture"}, {"kind", kind}, {"monotonic_ns", monotonic},
               {"thread_cpu_ns", cpu}});
}

void summary(std::ofstream& out, std::string type, std::uint64_t sample,
             std::size_t connection, bool hit, std::string status = "complete") {
    line(out, {{"type", type}, {"schema", 1}, {"record_kind", "connection_summary"},
               {"sample", sample}, {"connection", connection}, {"warmup", false},
               {"request_id", 1}, {"object_id", "fnv1a64:0000000000001234"},
               {"object_size", 123}, {"cache_hit", hit}, {"request_count", hit ? 0 : 1},
               {"logical_cache_bytes", hit ? 123 : 0}, {"cache_capacity", 256},
               {"reference_bytes", 123}, {"framework_reserved_bytes", 4096},
               {"tcp_start", {{"snd_mss", 1448}, {"rcv_mss", 1448},
                                {"total_retrans", 2}, {"bytes_acked", 10}}},
               {"tcp_end", {{"snd_mss", 1448}, {"rcv_mss", 1448},
                              {"total_retrans", sample == 1 ? 9 : 5},
                              {"bytes_acked", sample == 1 ? 210 : 110}}},
               {"artifact_status", status}, {"incomplete_reason", ""}});
}

void footer(std::ofstream& out, std::string type, std::uint64_t sample,
            std::string status = "complete") {
    line(out, {{"type", type}, {"schema", 1}, {"record_kind", "footer"},
               {"sample", sample}, {"artifact_status", status},
               {"incomplete_reason", ""}, {"capture_dropped", 0}});
}

void write_services(const std::filesystem::path& directory, std::uint64_t sample,
                    bool warm_second, bool omit_usable = false) {
    std::ofstream lookup(directory / "lookup.jsonl");
    line(lookup, service_header("certificate-lookup", sample, 2));
    for (std::size_t connection = 0; connection < 2; ++connection) {
        const bool hit = warm_second && connection == 1;
        event(lookup, "certificate-lookup", sample, connection, "SCENARIO_BEGIN", 100, 10);
        event(lookup, "certificate-lookup", sample, connection, "CACHE_LOOKUP", 105, 12);
        if (hit) {
            event(lookup, "certificate-lookup", sample, connection, "CACHE_HIT", 110, 14);
        } else {
            event(lookup, "certificate-lookup", sample, connection, "REQUEST_BEGIN", 110, 14);
            event(lookup, "certificate-lookup", sample, connection, "RESPONSE_COMPLETE", 150, 18);
        }
        if (!omit_usable)
            event(lookup, "certificate-lookup", sample, connection, "USABLE_OBJECT", 155, 19);
        event(lookup, "certificate-lookup", sample, connection, "SCENARIO_END", 250, 30);
        summary(lookup, "certificate-lookup", sample, connection, hit);
    }
    footer(lookup, "certificate-lookup", sample);

    std::ofstream ca(directory / "ca.jsonl");
    line(ca, service_header("mock-ca", sample, 4));
    for (std::size_t connection = 0; connection < 2; ++connection) {
        if (!(warm_second && connection == 1)) {
            event(ca, "mock-ca", sample, connection, "CA_PROCESS_BEGIN", 120, 40);
            event(ca, "mock-ca", sample, connection, "IO_SEND_ENTER", 125, 42);
            event(ca, "mock-ca", sample, connection, "IO_SEND_RETURN", 135, 43);
            event(ca, "mock-ca", sample, connection, "WAIT_BEGIN", 140, 44);
            event(ca, "mock-ca", sample, connection, "WAIT_END", 140, 45);
            event(ca, "mock-ca", sample, connection, "CA_PROCESS_END", 148, 48);
        }
        summary(ca, "mock-ca", sample, connection, warm_second && connection == 1);
    }
    footer(ca, "mock-ca", sample);
    write_tls(directory, sample);
}
} // namespace

int main() {
    const auto root = std::filesystem::temp_directory_path() /
                      ("turtle-lookup-report-" + std::to_string(::getpid()));
    const auto output = root / "report";
    std::filesystem::create_directories(root);
    {
        std::ofstream ledger(root / "attempts.jsonl");
        line(ledger, {{"type", "turtle-attempt-ledger"}, {"schema", 1},
                      {"record_kind", "run_config"}, {"requested_count", 5},
                      {"failure_policy", "fixed-attempts"}});
        line(ledger, ledger_row(1, "timeout", Json::array({0}),
                                Json::array({"1:scenario:begin", "1:scenario:end"})));
        line(ledger, ledger_row(2, "error", Json::array({0})));
        line(ledger, ledger_row(3, "incomplete", Json::array({0})));
        line(ledger, ledger_row(4, "success", Json::array({0, 1}),
                                Json::array({"4:setup:begin", "4:setup:end",
                                             "4:scenario:begin", "4:scenario:end",
                                             "4:cleanup:begin", "4:cleanup:end"})));
        line(ledger, ledger_summary(5, 4, 1, 1, 1, 1));
    }
    std::ofstream(root / "network-provenance.json")
        << Json({{"type", "turtle-network-provenance"}, {"schema", 1},
                 {"status", "complete"}, {"reason", nullptr},
                 {"director", {{"returncode", 0}}},
                 {"host_network_identity", {{"unchanged", true},
                                              {"before", {{"supported", true}}},
                                              {"after", {{"supported", true}}}}},
                 {"lifecycle", {{"namespace_fds_closed", true},
                                  {"owned_pipe_fds_closed", true}}},
                 {"cleanup", Json::array({{{"helper", "client"}, {"result", "reaped"}},
                                            {{"helper", "server"}, {"result", "reaped"}},
                                            {{"helper", "ca"}, {"result", "reaped"}},
                                            {{"helper", "router"}, {"result", "reaped"}},
                                            {{"observer", "reaped"}}})},
                 {"finished_monotonic_ns", 999},
                 {"condition_identity", {{"topology", "four-veth"},
                                          {"paths", {{{"logical", "ca_s2c"},
                                                       {"requested", {{"delay_ms", 5}, {"loss_percent", 20}}},
                                                       {"actual", {{"delay_ms", 5}, {"loss_percent", 20}}},
                                                       {"handle", "1:"}, {"drops", 7}}}},
                                          {"mtu", 1500},
                                          {"offloads", {{"requested", "off"}, {"actual", "off"}}},
                                          {"trace", {{"requested", true}}},
                                          {"namespace_pid", 999}, {"port", 45678}}}})
               .dump(2)
        << '\n';
    {
        std::ofstream observations(root / "network-observations.jsonl");
        for (const auto* id : {"1:scenario:begin", "1:scenario:end",
                               "4:setup:begin", "4:setup:end", "4:scenario:begin",
                               "4:scenario:end", "4:cleanup:begin", "4:cleanup:end"})
            line(observations, {{"type", "network-observation"}, {"schema", 1},
                                {"observation_id", id}, {"attempt", id[0] - '0'},
                                {"phase", std::string(id).find(":setup:") != std::string::npos
                                              ? "setup"
                                              : std::string(id).find(":cleanup:") != std::string::npos
                                                    ? "cleanup" : "scenario"},
                                {"edge", std::string(id).ends_with("begin") ? "begin" : "end"},
                                {"monotonic_ns", 100},
                                {"qdiscs", {{"ca_s2c", {{"drops", 7}}}}},
                                {"packet_trace", {{"packets", 3}}}});
    }
    for (std::uint64_t sample : {1, 4}) {
        const auto directory = root / ("sample-" + std::to_string(sample));
        std::filesystem::create_directory(directory);
        write_services(directory, sample, sample == 4, sample == 1);
    }

    const auto report = turtle::report::summarize_lookup(root, output);
    assert(report["network_integrity"][0]["integrity"]["status"] == "failed");
    assert(report["denominators"] == Json({{"requested", 5}, {"started", 4},
                                            {"success", 1}, {"timeout", 1}, {"error", 1},
                                            {"incomplete", 1}, {"not_attempted", 1}}));
    assert(report["attempt_table"][0]["final_status"] == "timeout");
    assert(report["attempt_table"][0]["connection_rows"].size() == 1);
    assert(report["attempt_table"][0]["artifacts"]["lookup.jsonl"] == "complete");
    assert(report["attempt_table"][4]["final_status"] == "not_attempted");
    assert(report["joined_rows"].size() == 5);
    const auto& timeout = report["joined_rows"][0];
    assert(timeout["attempt_status"] == "timeout");
    assert(timeout["usable_duration_ns"].is_null());
    assert(timeout["usable_duration_reason"] == "missing_lookup_request_or_usable_boundary");
    const auto& cold = report["joined_rows"][3];
    const auto& warm = report["joined_rows"][4];
    assert(cold["remote_lookup_duration_ns"] == 40);
    assert(cold["ca_process_ns"] == 28 && cold["ca_io_ns"] == 10 && cold["ca_wait_ns"] == 0);
    assert(cold["ca_wait_reason"].is_null());
    assert(cold["tcp_counter_deltas"]["lookup"]["deltas"]["total_retrans"] == 3);
    assert(timeout["tcp_counter_deltas"]["lookup"]["deltas"]["total_retrans"] == 7);
    assert(warm["cache_hit"] == true && warm["remote_lookup_duration_ns"].is_null());
    assert(warm["remote_lookup_duration_reason"] == "not_applicable_cache_hit");
    assert(warm["usable_duration_ns"] == 50);
    assert(warm["ca_process_ns"].is_null());
    assert(cold["network_observation_ids"].size() == 6);
    assert(cold["network_integrity"]["eligible"] == false);
    assert(cold["network_observation_reference_status"][0]["present"] == true);
    assert(report["network_observations"].size() == 8);
    assert(cold.contains("qdiscs") == false);
    assert(timeout["condition_identity"] == cold["condition_identity"]);
    assert(cold["condition_identity"] != warm["condition_identity"]);
    assert(cold["condition_identity"]["connection_position"] == 0);
    const auto& identity = report["condition_groups"][0]["condition_identity"]["network"];
    assert(identity.contains("namespace_pid") == false && identity.contains("port") == false);
    assert(identity["paths"][0].contains("drops") == false);
    assert(identity["paths"][0].contains("handle") == false);
    assert(std::filesystem::exists(output / "lookup-summary.json"));
    const auto provenance_path = root / "network-provenance.json";
    const auto saved_provenance_path = root / "network-provenance.saved";
    std::filesystem::rename(provenance_path, saved_provenance_path);
    const auto loopback_report =
        turtle::report::summarize_lookup(root, root / "loopback-report");
    std::filesystem::rename(saved_provenance_path, provenance_path);
    assert(loopback_report["joined_rows"][3]["automatic_comparison_eligible"] == false);
    assert(loopback_report["joined_rows"][3]["descriptive_distribution_eligible"] == true);
    bool retained_distribution = false;
    for (const auto& group : loopback_report["condition_groups"])
        for (const auto& reference : group["joined_rows"])
            if (reference == 3)
                retained_distribution =
                    group["distributions"]["tls_elapsed_ns"]["count"] == 1;
    assert(retained_distribution);

    auto rewrite_header = [](const std::filesystem::path& path, auto change) {
        std::ifstream input(path);
        std::string first;
        std::getline(input, first);
        const std::string rest{std::istreambuf_iterator<char>(input),
                               std::istreambuf_iterator<char>()};
        auto header = Json::parse(first);
        change(header);
        std::ofstream(path) << header.dump() << '\n' << rest;
    };
    const auto sample4 = root / "sample-4";
    assert(cold["condition_identity"]["client_endpoint"]["loaded_context"] ==
           Json({{"size", 0}, {"hash", ""}}));
    assert(cold["condition_identity"]["client_endpoint"]
               ["measurement_contract_revision"] == 1);
    assert(cold["condition_identity"]["server_endpoint"]
               ["measurement_contract_revision"] == 1);
    assert(cold["condition_identity"]["client_endpoint"]["measurement_controls"]
               ["channel_observer"] == true);
    assert(cold["condition_identity"]["server_endpoint"]["measurement_controls"]
               ["channel_observer"] == true);
    std::filesystem::rename(provenance_path, saved_provenance_path);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header.erase("measurement_contract_revision");
    });
    const auto legacy_client_contract =
        turtle::report::summarize_lookup(root, root / "legacy-client-contract-report");
    const auto& legacy_client_row = legacy_client_contract["joined_rows"][3];
    assert(legacy_client_row["condition_identity"]["client_endpoint"]
                            ["measurement_contract_revision"].is_null());
    assert(legacy_client_row["automatic_comparison_eligible"] == false);
    assert(legacy_client_row["descriptive_distribution_eligible"] == true);
    assert(std::find(legacy_client_row["comparison_exclusion_reasons"].begin(),
                     legacy_client_row["comparison_exclusion_reasons"].end(),
                     "missing_identity:client_measurement_contract_revision_unknown") !=
           legacy_client_row["comparison_exclusion_reasons"].end());
    bool legacy_client_distribution_retained = false;
    for (const auto& group : legacy_client_contract["condition_groups"])
        for (const auto& reference : group["joined_rows"])
            if (reference == 3)
                legacy_client_distribution_retained =
                    group["distributions"]["tls_elapsed_ns"]["count"] == 1;
    assert(legacy_client_distribution_retained);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["measurement_contract_revision"] = 1;
    });
    rewrite_header(sample4 / "server.jsonl", [](Json& header) {
        header.erase("measurement_contract_revision");
    });
    const auto legacy_server_contract =
        turtle::report::summarize_lookup(root, root / "legacy-server-contract-report");
    const auto& legacy_server_row = legacy_server_contract["joined_rows"][3];
    assert(legacy_server_row["condition_identity"]["server_endpoint"]
                            ["measurement_contract_revision"].is_null());
    assert(legacy_server_row["automatic_comparison_eligible"] == false);
    assert(std::find(legacy_server_row["comparison_exclusion_reasons"].begin(),
                     legacy_server_row["comparison_exclusion_reasons"].end(),
                     "missing_identity:server_measurement_contract_revision_unknown") !=
           legacy_server_row["comparison_exclusion_reasons"].end());
    rewrite_header(sample4 / "server.jsonl", [](Json& header) {
        header["measurement_contract_revision"] = 1;
    });
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["measurement_contract_revision"] = 2;
    });
    const auto different_contract =
        turtle::report::summarize_lookup(root, root / "different-contract-report");
    assert(different_contract["joined_rows"][3]["condition_identity"] !=
           cold["condition_identity"]);
    assert(different_contract["joined_rows"][3]["condition_identity"]
                             ["client_endpoint"]["measurement_contract_revision"] == 2);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["measurement_contract_revision"] = 1;
    });
    std::filesystem::rename(saved_provenance_path, provenance_path);
    for (const auto* role : {"client", "server"})
        rewrite_header(sample4 / (std::string(role) + ".jsonl"), [](Json& header) {
            header["config"]["channel_observer"] = false;
            header["observation_level"] = "observer-disabled";
        });
    const auto explicit_observer_off =
        turtle::report::summarize_lookup(root, root / "explicit-observer-off-report");
    const auto explicit_off_identity =
        explicit_observer_off["joined_rows"][3]["condition_identity"];
    assert(explicit_off_identity != cold["condition_identity"]);
    assert(explicit_off_identity["client_endpoint"]["measurement_controls"]
                                ["channel_observer"] == false);
    assert(explicit_off_identity["server_endpoint"]["measurement_controls"]
                                ["channel_observer"] == false);
    for (const auto* role : {"client", "server"})
        rewrite_header(sample4 / (std::string(role) + ".jsonl"), [](Json& header) {
            header["config"].erase("channel_observer");
        });
    const auto marker_only_off =
        turtle::report::summarize_lookup(root, root / "marker-only-observer-off-report");
    assert(marker_only_off["joined_rows"][3]["condition_identity"] == explicit_off_identity);
    assert(marker_only_off["joined_rows"][3]["condition_identity"] != cold["condition_identity"]);

    rewrite_header(sample4 / "server.jsonl", [](Json& header) {
        header["observation_level"] = "L0";
    });
    const auto client_only_off =
        turtle::report::summarize_lookup(root, root / "client-only-observer-off-report");
    const auto client_only_identity = client_only_off["joined_rows"][3]["condition_identity"];
    assert(client_only_identity != cold["condition_identity"] &&
           client_only_identity != explicit_off_identity);
    assert(client_only_identity["client_endpoint"]["measurement_controls"]
                               ["channel_observer"] == false);
    assert(client_only_identity["server_endpoint"]["measurement_controls"]
                               ["channel_observer"] == true);

    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["observation_level"] = "L0";
    });
    rewrite_header(sample4 / "server.jsonl", [](Json& header) {
        header["observation_level"] = "observer-disabled";
    });
    const auto server_only_off =
        turtle::report::summarize_lookup(root, root / "server-only-observer-off-report");
    const auto server_only_identity = server_only_off["joined_rows"][3]["condition_identity"];
    assert(server_only_identity != cold["condition_identity"] &&
           server_only_identity != explicit_off_identity &&
           server_only_identity != client_only_identity);
    assert(server_only_identity["client_endpoint"]["measurement_controls"]
                               ["channel_observer"] == true);
    assert(server_only_identity["server_endpoint"]["measurement_controls"]
                               ["channel_observer"] == false);
    rewrite_header(sample4 / "server.jsonl", [](Json& header) {
        header["observation_level"] = "L0";
    });
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["loaded_context_size"] = 8;
        header["loaded_context_hash"] = "context-a";
    });
    const auto context_a = turtle::report::summarize_lookup(root, root / "context-a-report");
    assert(context_a["joined_rows"][3]["condition_identity"] != cold["condition_identity"]);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["loaded_context_hash"] = "context-b";
    });
    const auto context_b = turtle::report::summarize_lookup(root, root / "context-b-report");
    assert(context_b["joined_rows"][3]["condition_identity"] !=
           context_a["joined_rows"][3]["condition_identity"]);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header.erase("loaded_context_size");
        header.erase("loaded_context_hash");
    });
    const auto context_missing =
        turtle::report::summarize_lookup(root, root / "context-missing-report");
    assert(context_missing["joined_rows"][3]["automatic_comparison_eligible"] == false);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["loaded_context_size"] = 0;
        header["loaded_context_hash"] = "";
    });
    rewrite_header(sample4 / "lookup.jsonl", [](Json& header) { header["mode"] = "memory"; });
    const auto memory_report = turtle::report::summarize_lookup(root, root / "memory-report");
    assert(memory_report["joined_rows"][3]["condition_identity"] != cold["condition_identity"]);
    assert(memory_report["condition_groups"][0]["timing_interpretation"] == "diagnostic_only" ||
           memory_report["condition_groups"][1]["timing_interpretation"] == "diagnostic_only");
    rewrite_header(sample4 / "lookup.jsonl", [](Json& header) { header["mode"] = "timing"; });
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["config"]["client_adapter"] = "different-client";
    });
    const auto adapter_report = turtle::report::summarize_lookup(root, root / "adapter-report");
    assert(adapter_report["joined_rows"][3]["condition_identity"] != cold["condition_identity"]);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["config"]["client_adapter"] = "fixture-client";
    });
    rewrite_header(sample4 / "lookup.jsonl", [](Json& header) {
        header.erase("initial_cache_bytes");
    });
    const auto no_initial = turtle::report::summarize_lookup(root, root / "no-initial-report");
    assert(no_initial["joined_rows"][3]["automatic_comparison_eligible"] == false);
    rewrite_header(sample4 / "lookup.jsonl", [](Json& header) { header["initial_cache_bytes"] = 0; });
    auto rewrite_rows = [](const std::filesystem::path& path, auto change) {
        std::ifstream input(path);
        std::vector<Json> rows;
        std::string text;
        while (std::getline(input, text))
            if (!text.empty()) {
                auto row = Json::parse(text);
                change(row);
                rows.push_back(std::move(row));
            }
        std::ofstream output(path);
        for (const auto& row : rows)
            output << row.dump() << '\n';
    };
    rewrite_rows(sample4 / "lookup.jsonl", [](Json& row) {
        if (row.value("record_kind", "") == "connection_summary" &&
            row.value("connection", std::size_t(-1)) == 0)
            row["tcp_start"]["snd_mss"] = 1300;
    });
    const auto mss_changed = turtle::report::summarize_lookup(root, root / "mss-report");
    assert(mss_changed["joined_rows"][3]["condition_identity"] != cold["condition_identity"]);
    rewrite_rows(sample4 / "lookup.jsonl", [](Json& row) {
        if (row.value("record_kind", "") == "connection_summary" &&
            row.value("connection", std::size_t(-1)) == 0)
            row["tcp_start"]["snd_mss"] = nullptr;
    });
    const auto mss_missing = turtle::report::summarize_lookup(root, root / "mss-missing-report");
    assert(mss_missing["joined_rows"][3]["automatic_comparison_eligible"] == false);
    rewrite_rows(sample4 / "lookup.jsonl", [](Json& row) {
        if (row.value("record_kind", "") == "connection_summary" &&
            row.value("connection", std::size_t(-1)) == 0)
            row["tcp_start"]["snd_mss"] = 1448;
    });
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["config"].erase("timeout_ms");
    });
    const auto policy_missing =
        turtle::report::summarize_lookup(root, root / "policy-missing-report");
    assert(policy_missing["joined_rows"][3]["automatic_comparison_eligible"] == false);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["config"]["timeout_ms"] = 10000;
        header["connections"][0]["socket"].erase("receive_buffer");
    });
    const auto socket_field_missing =
        turtle::report::summarize_lookup(root, root / "socket-field-missing-report");
    assert(socket_field_missing["joined_rows"][3]["automatic_comparison_eligible"] == false);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["connections"][0]["socket"]["receive_buffer"] = 2048;
    });

    for (const auto* role : {"client", "server"})
        rewrite_header(sample4 / (std::string(role) + ".jsonl"), [](Json& header) {
            header["config"]["warmups"] = 1;
            header["config"]["connections"] = 1;
            header["connections"][1]["warmup"] = true;
        });
    for (const auto* artifact : {"lookup", "ca"})
        rewrite_rows(sample4 / (std::string(artifact) + ".jsonl"), [](Json& row) {
            if (row.value("record_kind", "") == "connection_summary" &&
                row.value("connection", std::size_t(-1)) == 1)
                row["warmup"] = true;
        });
    std::filesystem::rename(provenance_path, saved_provenance_path);
    const auto warmup_baseline =
        turtle::report::summarize_lookup(root, root / "warmup-baseline-report");
    assert(warmup_baseline["joined_rows"][4]["warmup"] == true);
    const auto warmup_identity =
        warmup_baseline["joined_rows"][3]["condition_identity"];
    const auto warmup_group = warmup_baseline["joined_rows"][4]["condition_identity"];
    bool warmup_metrics_excluded = false;
    bool measured_metrics_retained = false;
    for (const auto& group : warmup_baseline["condition_groups"])
        if (group["condition_identity"] == warmup_group) {
            warmup_metrics_excluded =
                group["distributions"]["tls_elapsed_ns"]["count"] == 0;
        } else if (group["condition_identity"] == warmup_identity) {
            measured_metrics_retained =
                group["distributions"]["tls_elapsed_ns"]["count"] == 1;
        }
    assert(warmup_metrics_excluded);
    assert(measured_metrics_retained);

    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["connections"][1]["socket"]["send_buffer"] = 4096;
    });
    const auto warmup_socket_changed =
        turtle::report::summarize_lookup(root, root / "warmup-socket-changed-report");
    assert(warmup_socket_changed["joined_rows"][3]["condition_identity"] != warmup_identity);
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["connections"][1]["socket"]["send_buffer"] = 1024;
    });
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["connections"][1].erase("socket");
    });
    const auto warmup_socket_missing =
        turtle::report::summarize_lookup(root, root / "warmup-socket-missing-report");
    assert(warmup_socket_missing["joined_rows"][3]["automatic_comparison_eligible"] == false);
    assert(std::find(warmup_socket_missing["joined_rows"][3]
                         ["comparison_exclusion_reasons"].begin(),
                     warmup_socket_missing["joined_rows"][3]
                         ["comparison_exclusion_reasons"].end(),
                     "missing_identity:connection_policy_incomplete") !=
           warmup_socket_missing["joined_rows"][3]
               ["comparison_exclusion_reasons"].end());
    rewrite_header(sample4 / "client.jsonl", [](Json& header) {
        header["connections"][1]["socket"] = {
            {"nonblocking", true}, {"tcp_nodelay", true}, {"send_buffer", 1024},
            {"receive_buffer", 2048}, {"kernel_timestamps", false}};
    });
    for (const auto* role : {"client", "server"})
        rewrite_header(sample4 / (std::string(role) + ".jsonl"), [](Json& header) {
            header["config"]["warmups"] = 0;
            header["config"]["connections"] = 2;
            header["connections"][1]["warmup"] = false;
        });
    for (const auto* artifact : {"lookup", "ca"})
        rewrite_rows(sample4 / (std::string(artifact) + ".jsonl"), [](Json& row) {
            if (row.value("record_kind", "") == "connection_summary" &&
                row.value("connection", std::size_t(-1)) == 1)
                row["warmup"] = false;
        });
    std::filesystem::rename(saved_provenance_path, provenance_path);

    const auto tls_report = turtle::report::summarize(root, root / "tls-report");
    assert(tls_report["invalid_samples"] >= 1);
    assert(tls_report["comparisons"].empty());
    for (const auto& group : tls_report["groups"])
        assert(group["dimensions"]["automatic_comparison_identity_complete"] == false);

    auto changed_provenance = Json::parse(std::ifstream(root / "network-provenance.json"));
    changed_provenance["condition_identity"]["namespace_pid"] = 123456;
    changed_provenance["condition_identity"]["port"] = 54321;
    changed_provenance["condition_identity"]["paths"][0]["drops"] = 999;
    std::ofstream(root / "network-provenance.json") << changed_provenance.dump(2) << '\n';
    const auto volatile_changed = turtle::report::summarize_lookup(root, root / "volatile-report");
    assert(volatile_changed["condition_groups"][0]["condition_identity"] ==
           report["condition_groups"][0]["condition_identity"]);
    changed_provenance["host_network_identity"]["unchanged"] = false;
    std::ofstream(root / "network-provenance.json") << changed_provenance.dump(2) << '\n';
    const auto host_changed = turtle::report::summarize_lookup(root, root / "host-changed-report");
    assert(host_changed["joined_rows"][3]["condition_identity"] == cold["condition_identity"]);
    assert(host_changed["joined_rows"][3]["network_integrity"]["eligible"] == false);
    changed_provenance["host_network_identity"]["unchanged"] = true;
    changed_provenance["status"] = "cleanup-failed";
    changed_provenance["lifecycle"]["namespace_fds_closed"] = false;
    std::ofstream(root / "network-provenance.json") << changed_provenance.dump(2) << '\n';
    const auto cleanup_failed =
        turtle::report::summarize_lookup(root, root / "cleanup-failed-report");
    assert(cleanup_failed["joined_rows"][3]["condition_identity"] == cold["condition_identity"]);
    assert(cleanup_failed["joined_rows"][3]["network_integrity"]["eligible"] == false);
    changed_provenance["status"] = "complete";
    changed_provenance["lifecycle"]["namespace_fds_closed"] = true;
    std::ofstream(root / "network-provenance.json") << changed_provenance.dump(2) << '\n';
    const auto observations_path = root / "network-observations.jsonl";
    std::ifstream observation_input(observations_path);
    const std::string saved_observations{std::istreambuf_iterator<char>(observation_input),
                                         std::istreambuf_iterator<char>()};
    observation_input.close();
    std::ofstream(observations_path) <<
        "{\"type\":\"network-observation\",\"schema\":1,\"observation_id\":\"4:scenario:begin\"}\n";
    const auto missing_observation =
        turtle::report::summarize_lookup(root, root / "missing-observation-report");
    assert(missing_observation["joined_rows"][3]["network_integrity"]["eligible"] == false);
    std::ofstream(observations_path) << saved_observations;
    changed_provenance["condition_identity"]["offloads"]["actual"] = "on";
    std::ofstream(root / "network-provenance.json") << changed_provenance.dump(2) << '\n';
    const auto stable_changed = turtle::report::summarize_lookup(root, root / "stable-report");
    assert(stable_changed["condition_groups"][0]["condition_identity"] !=
           report["condition_groups"][0]["condition_identity"]);
    changed_provenance["condition_identity"].erase("offloads");
    std::ofstream(root / "network-provenance.json") << changed_provenance.dump(2) << '\n';
    const auto missing_identity = turtle::report::summarize_lookup(root, root / "missing-report");
    assert(missing_identity["condition_groups"][0]["automatic_comparison_eligible"] == false);

    const auto legacy = root / "legacy";
    std::filesystem::create_directories(legacy / "sample");
    write_tls(legacy / "sample", 9);
    auto server = tls_header(9);
    server["role"] = "server";
    std::ofstream(legacy / "sample" / "server.jsonl") << server.dump() << '\n';
    std::ofstream(legacy / "sample" / "director.txt") << "invalid: child failed\n";
    const auto legacy_report = turtle::report::summarize_lookup(legacy, legacy / "report");
    assert(legacy_report["attempt_ledger_status"] ==
           "absent_using_legacy_tls_and_director_fallback");
    assert(legacy_report["denominators"]["error"] == 1);
    assert(legacy_report["attempt_table"][0]["source"] == "legacy_tls_director_fallback");

    const auto multi = root / "multi-run";
    for (const auto* run_name : {"run-a", "run-b"}) {
        std::filesystem::create_directories(multi / run_name);
        std::ofstream ledger(multi / run_name / "attempts.jsonl");
        line(ledger, {{"type", "turtle-attempt-ledger"}, {"schema", 1},
                      {"record_kind", "run_config"}, {"requested_count", 1},
                      {"failure_policy", "fixed-attempts"}});
        line(ledger, ledger_row(1, "success", Json::array()));
        line(ledger, ledger_summary(1, 1, 1, 0, 0, 0));
    }
    const auto multi_report = turtle::report::summarize_lookup(multi, multi / "report");
    assert(multi_report["denominators"]["requested"] == 2);
    assert(multi_report["denominators"]["success"] == 2);
    assert(multi_report["attempt_table"].size() == 2);
    assert(multi_report["attempt_table"][0]["attempt_id"] == 1 &&
           multi_report["attempt_table"][1]["attempt_id"] == 1);
    assert(multi_report["attempt_table"][0]["run_id"] !=
           multi_report["attempt_table"][1]["run_id"]);

    auto require_bad_ledger = [&](const char* name, const std::string& contents) {
        const auto invalid = root / name;
        std::filesystem::create_directories(invalid);
        std::ofstream(invalid / "attempts.jsonl") << contents;
        bool rejected = false;
        try {
            (void)turtle::report::summarize_lookup(invalid, invalid / "report");
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        assert(rejected);
    };
    require_bad_ledger("empty-ledger", "");
    require_bad_ledger("malformed-ledger", "{broken\n");
    const std::string config =
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
        "\"record_kind\":\"run_config\",\"requested_count\":1}\n";
    require_bad_ledger("malformed-middle-ledger", config + "{broken\n" +
        ledger_summary(1, 0, 0, 0, 0, 0).dump() + "\n");
    require_bad_ledger("header-then-garbage-ledger", config + "{broken\n");
    require_bad_ledger("invalid-schema-ledger", config +
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":2,"
        "\"record_kind\":\"attempt_started\",\"attempt_id\":1}\n");
    require_bad_ledger("wrong-type-terminal-ledger", config +
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":\"1\","
        "\"record_kind\":\"attempt_started\",\"attempt_id\":1}\n");
    require_bad_ledger("invalid-kind-ledger", config +
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
        "\"record_kind\":\"unknown\",\"attempt_id\":1}\n");
    require_bad_ledger("missing-summary-ledger", config +
        ledger_row(1, "success", Json::array()).dump() + "\n");
    require_bad_ledger("truncated-summary-ledger", config +
        ledger_row(1, "success", Json::array()).dump() + "\n" +
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
        "\"record_kind\":\"run_summary\",\"requested\":" );
    require_bad_ledger("invalid-id-ledger", config +
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
        "\"record_kind\":\"attempt_started\",\"attempt_id\":2}\n");
    require_bad_ledger("invalid-summary-ledger", config +
        ledger_summary(1, 1, 0, 0, 0, 0).dump() + "\n");
    require_bad_ledger("row-after-summary-ledger", config +
        ledger_summary(1, 0, 0, 0, 0, 0).dump() + "\n" +
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
        "\"record_kind\":\"attempt_started\",\"attempt_id\":1}\n");

    const auto partial = root / "partial-ledger";
    std::filesystem::create_directories(partial);
    std::ofstream(partial / "attempts.jsonl")
        << config
        << "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
           "\"record_kind\":\"attempt_started\",\"attempt_id\":1}\n"
        << "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
           "\"record_kind\":\"attempt_final\",\"attempt_id\":";
    const auto partial_report =
        turtle::report::summarize_lookup(partial, partial / "report");
    assert(partial_report["attempt_ledger_status"] == "authoritative_partial");
    assert(partial_report["attempt_table"][0]["final_status"] == "incomplete");

    const auto nonregular = root / "nonregular-ledger";
    std::filesystem::create_directories(nonregular / "attempts.jsonl");
    bool nonregular_rejected = false;
    try {
        (void)turtle::report::summarize_lookup(nonregular, nonregular / "report");
    } catch (const std::runtime_error&) {
        nonregular_rejected = true;
    }
    assert(nonregular_rejected);

    std::filesystem::remove_all(root);
    std::cout << "lookup report tests passed\n";
}
