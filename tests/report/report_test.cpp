#include "report/prototype.hpp"
#include "report/report.hpp"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <numeric>
#include <sstream>
#include <unistd.h>

// Candidate cases assert client statistics. Their peers now carry complete raw
// boundaries too, so select the client view explicitly instead of relying on
// header-only peers being discarded as invalid local measurements.
nlohmann::json client_report(const std::filesystem::path& input,
                            const std::filesystem::path& output, bool repeated = false) {
    auto report = turtle::report::summarize(input, output, repeated);
    using J = nlohmann::json;
    J groups = J::array(), comparisons = J::array();
    std::map<std::size_t, std::size_t> indices;
    for (std::size_t i = 0; i < report["groups"].size(); ++i)
        if (report["groups"][i]["dimensions"]["role"] == "client") {
            indices.emplace(i, groups.size());
            groups.push_back(report["groups"][i]);
        }
    for (auto comparison : report["comparisons"]) {
        const auto a = comparison["group_a"].get<std::size_t>();
        const auto b = comparison["group_b"].get<std::size_t>();
        if (indices.contains(a) && indices.contains(b)) {
            comparison["group_a"] = indices.at(a);
            comparison["group_b"] = indices.at(b);
            comparisons.push_back(comparison);
        }
    }
    report["groups"] = std::move(groups);
    report["comparisons"] = std::move(comparisons);
    return report;
}

int main() {
    using namespace turtle::report;
    for (std::size_t n = 1; n < 40; ++n) {
        std::vector<double> v(n);
        std::iota(v.begin(), v.end(), 1.0);
        std::reverse(v.begin(), v.end());
        const auto got = statistics(v);
        std::vector<double> repeated;
        for (double x : v)
            for (int i = 0; i < 8; ++i)
                repeated.push_back(x);
        std::sort(repeated.begin(), repeated.end());
        for (int q = 0; q < 3; ++q) {
            const auto begin = (1 + 2 * q) * n, end = (3 + 2 * q) * n;
            double expected =
                std::accumulate(repeated.begin() + begin, repeated.begin() + end, 0.0) / (2 * n);
            assert(std::abs(got.stq[q] - expected) < 1e-10);
        }
        std::sort(v.begin(), v.end());
        assert(statistics(v).stq == got.stq);
    }
    const std::vector<double> a{1, 1, 1}, b{3, 3, 3};
    auto c = compare(a, b, 7, 100);
    assert(c.difference == 2 && c.lower == 2 && c.upper == 2 && c.distinguishable);
    assert(!compare(a, a, 7, 100).distinguishable);
    using J = nlohmann::json;
    J unobserved = {{"measurement_contract_revision", 3},
                    {"adapter_connection", {{"mode", "module"}}},
                    {"role", "client"},
                    {"mode", "timing"},
                    {"config", {{"tls", {{"framework_io", false}}}}},
                    {"declaration", J::object()}};
    auto unobserved_prototype = prototype_observations(unobserved, {}, 0, nullptr);
    assert(unobserved_prototype["windows"]["open_to_client_finished_submit"]["status"] ==
           "unsupported");
    assert(unobserved_prototype["internal_spans_status"] == "unsupported");
    assert(unobserved_prototype["internal_spans_complete"].is_null());
    unobserved["role"] = "server";
    unobserved["mode"] = "trace";
    unobserved["config"]["tls"]["framework_io"] = true;
    assert(prototype_observations(
               unobserved, {}, 0,
               nullptr)["windows"]["first_tls_receive_to_client_finished_processed"]["status"] ==
           "unsupported");
    J header = {{"role", "client"},
                {"connections", J::array({{{"index", 0},
                                           {"warmup", false},
                                           {"application_verified", true},
                                           {"scenario_completed", true},
                                           {"end_sequence", 8}}})}};
    std::vector<J> events;
    auto add = [&](const char* kind, int time, const char* call = "handshake", int result = 0) {
        events.push_back({{"sequence", events.size() + 1},
                          {"kind", kind},
                          {"monotonic_ns", time},
                          {"call", call},
                          {"result", result},
                          {"location", "implementation_boundary"},
                          {"connection", 0}});
    };
    add("CALL_BEGIN", 10);
    add("IO_SEND_ENTER", 12);
    add("IO_SEND_RETURN", 15);
    add("CALL_END", 20);
    add("WAIT_BEGIN", 21);
    add("WAIT_END", 30);
    add("CALL_BEGIN", 31, "app_recv");
    add("CALL_END", 40, "app_recv", 2);
    auto p = partition(header, events)[0];
    assert(p["valid"] == true && p["elapsed_ns"] == 30);
    assert(p["computation_ns"] == 16 && p["io_ns"] == 3 && p["wait_ns"] == 9 && p["gap_ns"] == 2);
    auto native_client = header;
    native_client["observation_level"] = "library-only";
    native_client["config"] = {{"tls", {{"framework_io", false}}}};
    native_client["availability"] = {
        {"tls_stream", {{"available", false}, {"reason", "native_socket_io_not_observed"}}},
        {"io_events", {{"available", false}, {"reason", "native_socket_io_not_observed"}}}};
    auto native_client_part = partition(native_client, events)[0];
    assert(native_client_part["valid"] == true && native_client_part["elapsed_ns"] == 30);
    assert(native_client_part["io_ns"].is_null() && native_client_part["computation_ns"].is_null());
    assert(native_client_part["io_breakdown"]["available"] == false);
    auto native_server = native_client;
    native_server["role"] = "server";
    native_server["connections"][0]["application_verified"] = true;
    native_server["connections"][0]["primary_window"] = {
        {"available", false}, {"reason", "server_first_receive_not_observed"}};
    auto native_server_part = partition(native_server, events)[0];
    assert(native_server_part["valid"] == true);
    assert(native_server_part["primary_window"]["available"] == false);
    assert(native_server_part["reason"] == "server_first_receive_not_observed");
    assert(native_server_part["io_breakdown"]["reason"] == "io_events_not_observed");
    assert(!native_server_part.contains("elapsed_ns"));
    auto callback_partial = header;
    callback_partial["connections"][0]["primary_window"] = {
        {"available", false}, {"reason", "measurement_boundaries_incomplete"}};
    const auto callback_partial_part = partition(callback_partial, events)[0];
    assert(callback_partial_part["valid"] == true);
    assert(callback_partial_part["io_breakdown"]["available"] == false);
    assert(callback_partial_part["io_breakdown"]["reason"] == "measurement_boundaries_incomplete");
    auto unverified_application = header;
    unverified_application["connections"][0]["application_verified"] = false;
    unverified_application["connections"][0]["scenario_completed"] = false;
    const auto unverified_part = partition(unverified_application, events)[0];
    assert(unverified_part["primary_window"]["available"] == true);
    assert(unverified_part["elapsed_ns"] == 30);
    assert(unverified_part["valid"] == false);
    unverified_application["connections"][0].erase("application_verified");
    assert(partition(unverified_application, events)[0]["valid"] == false);

    auto common_header = header;
    common_header["connections"][0]["end_sequence"] = 6;
    common_header["config"] = {{"tls", {{"application_bytes", 4}}}, {"channel_observer", true}};
    auto common_events = [](std::string role, bool observer) {
        J rows = J::array({
            {{"kind", "CALL_BEGIN"},
             {"call", "handshake"},
             {"sequence", 1},
             {"monotonic_ns", 100},
             {"thread_cpu_ns", 10},
             {"location", "implementation_boundary"},
             {"connection", 0}},
        });
        if (observer) {
            rows.push_back({{"kind", "IO_RECV_ENTER"},
                            {"call", "handshake"},
                            {"sequence", 2},
                            {"monotonic_ns", 120},
                            {"thread_cpu_ns", 20},
                            {"location", "framework"},
                            {"connection", 0}});
            rows.push_back({{"kind", "IO_RECV_RETURN"},
                            {"call", "handshake"},
                            {"sequence", 3},
                            {"monotonic_ns", 130},
                            {"thread_cpu_ns", 25},
                            {"transferred", 1},
                            {"location", "framework"},
                            {"connection", 0}});
        }
        rows.push_back({{"kind", "CALL_END"},
                        {"call", "handshake"},
                        {"sequence", 4},
                        {"monotonic_ns", 140},
                        {"thread_cpu_ns", 30},
                        {"result", 2},
                        {"location", "implementation_boundary"},
                        {"connection", 0}});
        const auto target = role == "client" ? "app_recv" : "app_send";
        rows.push_back({{"kind", "CALL_BEGIN"},
                        {"call", target},
                        {"sequence", 5},
                        {"monotonic_ns", role == "client" ? 350 : 450},
                        {"thread_cpu_ns", 40},
                        {"location", "implementation_boundary"},
                        {"connection", 0}});
        rows.push_back({{"kind", "CALL_END"},
                        {"call", target},
                        {"sequence", 6},
                        {"monotonic_ns", role == "client" ? 400 : 500},
                        {"thread_cpu_ns", role == "client" ? 70 : 90},
                        {"result", 2},
                        {"transferred", 4},
                        {"location", "implementation_boundary"},
                        {"connection", 0}});
        return rows.get<std::vector<J>>();
    };
    for (bool observer : {true, false}) {
        common_header["config"]["channel_observer"] = observer;
        if (observer)
            common_header.erase("availability");
        else
            common_header["availability"] = {
                {"io_events", {{"available", false}, {"reason", "channel_observer_disabled"}}}};
        const auto common_part = partition(common_header, common_events("client", observer))[0];
        const auto common_client = common_part["handshake_call_begin_to_application_complete"];
        assert(common_client["available"] == true && common_client["elapsed_ns"] == 300);
        assert(common_client["thread_cpu_ns"] == 60 &&
               common_client["thread_cpu_reason"].is_null());
        assert(common_client["start_event_sequence"] == 1 &&
               common_client["end_event_sequence"] == 6);
        if (!observer)
            assert(common_part["io_ns"].is_null() && common_part["computation_ns"].is_null());
    }
    common_header.erase("availability");
    const auto stripped_off_client = partition(common_header, common_events("client", false))[0];
    assert(stripped_off_client["valid"] == true && stripped_off_client["elapsed_ns"] == 300);
    assert(stripped_off_client["io_breakdown"]["available"] == false &&
           stripped_off_client["io_breakdown"]["reason"] == "io_events_not_observed");
    assert(stripped_off_client["io_ns"].is_null() &&
           stripped_off_client["computation_ns"].is_null());
    assert(stripped_off_client["handshake_call_begin_to_application_complete"]["available"] ==
           true);
    auto common_server_header = common_header;
    common_server_header["role"] = "server";
    common_server_header["config"]["channel_observer"] = true;
    auto common_server_on = partition(common_server_header, common_events("server", true))[0];
    assert(common_server_on["elapsed_ns"] == 370);
    assert(common_server_on["handshake_call_begin_to_application_complete"]["elapsed_ns"] == 400);
    common_server_header["config"]["channel_observer"] = false;
    common_server_header["availability"] = {
        {"io_events", {{"available", false}, {"reason", "channel_observer_disabled"}}}};
    common_server_header["connections"][0]["primary_window"] = {
        {"available", false}, {"reason", "server_first_receive_not_observed"}};
    auto common_server_off = partition(common_server_header, common_events("server", false))[0];
    assert(!common_server_off.contains("elapsed_ns"));
    assert(common_server_off["handshake_call_begin_to_application_complete"]["available"] == true);
    assert(common_server_off["handshake_call_begin_to_application_complete"]["elapsed_ns"] == 400);
    auto stripped_off_server = common_server_header;
    stripped_off_server.erase("availability");
    stripped_off_server["connections"][0].erase("primary_window");
    stripped_off_server["config"].erase("channel_observer");
    stripped_off_server["observation_level"] = "observer-disabled";
    const auto stripped_server_part =
        partition(stripped_off_server, common_events("server", false))[0];
    assert(stripped_server_part["valid"] == true);
    assert(stripped_server_part["primary_window"]["available"] == false &&
           stripped_server_part["reason"] == "server_first_receive_not_observed");
    assert(!stripped_server_part.contains("elapsed_ns"));
    assert(stripped_server_part["io_breakdown"]["reason"] == "io_events_not_observed");
    assert(stripped_server_part["handshake_call_begin_to_application_complete"]["available"] ==
           true);
    assert(stripped_server_part["handshake_call_begin_to_application_complete"]["elapsed_ns"] ==
           400);

    auto progress_events = common_events("client", false);
    progress_events.pop_back();
    progress_events.pop_back();
    auto append_progress = [&](int sequence, int timestamp, const char* kind, int result,
                               int transferred) {
        progress_events.push_back({{"kind", kind},
                                   {"call", "app_recv"},
                                   {"sequence", sequence},
                                   {"monotonic_ns", timestamp},
                                   {"thread_cpu_ns", timestamp / 10},
                                   {"result", result},
                                   {"transferred", transferred},
                                   {"location", "implementation_boundary"},
                                   {"connection", 0}});
    };
    append_progress(5, 200, "CALL_BEGIN", 0, 0);
    append_progress(6, 210, "CALL_END", 0, 0);
    append_progress(7, 250, "CALL_BEGIN", 0, 0);
    append_progress(8, 300, "CALL_END", 2, 1);
    append_progress(9, 350, "CALL_BEGIN", 0, 0);
    append_progress(10, 400, "CALL_END", 2, 3);
    auto progress = partition(common_header,
                              progress_events)[0]["handshake_call_begin_to_application_complete"];
    assert(progress["available"] == true && progress["elapsed_ns"] == 300 &&
           progress["end_event_sequence"] == 10);
    auto missing_cpu = progress_events;
    missing_cpu.back()["thread_cpu_ns"] = nullptr;
    auto elapsed_without_cpu =
        partition(common_header, missing_cpu)[0]["handshake_call_begin_to_application_complete"];
    assert(elapsed_without_cpu["available"] == true && elapsed_without_cpu["elapsed_ns"] == 300);
    assert(elapsed_without_cpu["thread_cpu_ns"].is_null() &&
           elapsed_without_cpu["thread_cpu_reason"] == "thread_cpu_snapshot_missing");
    auto cpu_regression = progress_events;
    cpu_regression.back()["thread_cpu_ns"] = 1;
    const auto elapsed_with_cpu_regression =
        partition(common_header, cpu_regression)[0]["handshake_call_begin_to_application_complete"];
    assert(elapsed_with_cpu_regression["available"] == true &&
           elapsed_with_cpu_regression["elapsed_ns"] == 300 &&
           elapsed_with_cpu_regression["thread_cpu_ns"].is_null() &&
           elapsed_with_cpu_regression["thread_cpu_reason"] == "thread_cpu_regression");
    auto time_regression = progress_events;
    time_regression.back()["monotonic_ns"] = 99;
    assert(
        partition(common_header,
                  time_regression)[0]["handshake_call_begin_to_application_complete"]["reason"] ==
        "boundary_event_order_or_time_regression");
    auto sequence_regression = progress_events;
    sequence_regression.back()["sequence"] = 1;
    assert(
        partition(
            common_header,
            sequence_regression)[0]["handshake_call_begin_to_application_complete"]["available"] ==
        false);
    auto incomplete_progress = progress_events;
    incomplete_progress.back()["transferred"] = 2;
    assert(partition(
               common_header,
               incomplete_progress)[0]["handshake_call_begin_to_application_complete"]["reason"] ==
           "application_completion_missing");
    auto unverified_common = common_header;
    unverified_common["connections"][0]["application_verified"] = false;
    assert(
        partition(unverified_common,
                  progress_events)[0]["handshake_call_begin_to_application_complete"]["reason"] ==
        "application_not_verified");
    auto isolated_connections = common_header;
    isolated_connections["connections"].push_back(
        {{"index", 1}, {"warmup", true}, {"application_verified", true}});
    auto foreign_events = progress_events;
    for (auto& event : foreign_events) {
        event["connection"] = 1;
        event["monotonic_ns"] = event["monotonic_ns"].get<int>() + 10000;
    }
    auto mixed_events = progress_events;
    mixed_events.insert(mixed_events.end(), foreign_events.begin(), foreign_events.end());
    const auto isolated = partition(isolated_connections, mixed_events);
    assert(isolated.size() == 1);
    assert(isolated[0]["handshake_call_begin_to_application_complete"]["elapsed_ns"] == 300);
    for (auto& e : events) {
        e["thread_cpu_ns"] = e["monotonic_ns"];
        e["cycles"] = 2 * e["monotonic_ns"].get<unsigned>();
        e["instructions"] = 3 * e["monotonic_ns"].get<unsigned>();
    }
    header["perf_complete"] = true;
    auto measured = partition(header, events)[0];
    assert(measured["thread_cpu_ns"] == 30 && measured["cycles"] == 60 &&
           measured["instructions"] == 90);
    header["perf_complete"] = false;
    assert(partition(header, events)[0]["cycles"].is_null());
    for (auto& event : events)
        event["heap"] = {{"live", 10}, {"interval_peak", 10}};
    events.front()["heap"] = {{"live", 10}, {"interval_peak", 1000}};
    events.back()["heap"] = {{"live", 10}, {"interval_peak", 20}};
    assert(partition(header, events)[0]["heap_peak_bytes"] == 20);
    auto kernel = events.front();
    kernel["location"] = "kernel";
    kernel["monotonic_ns"] = 999999;
    events.insert(events.begin() + 2, kernel);
    for (std::size_t i = 0; i < events.size(); ++i)
        events[i]["sequence"] = i + 1;
    header["connections"][0]["end_sequence"] = events.size();
    assert(partition(header, events)[0]["elapsed_ns"] == 30);
    header.update({{"schema", 3},
                   {"measurement_contract_revision", 3},
                   {"run_id", "report-fixture"},
                   {"context_id", "context"},
                   {"scenario", J::object()},
                   {"adapter_connection", {{"mode", "module"}, {"tls_linkage", "fixture"}}},
                   {"type", "sample"},
                   {"sample", 1},
                   {"batch", 1},
                   {"valid", true},
                   {"profile_hash", "test"},
                   {"environment_hash", "env"},
                   {"mode", "timing"},
                   {"config", {{"tls", J::object()}}},
                   {"declaration", {{"library", "fixture"}, {"is_mock", true}}}});
    const auto dir =
        std::filesystem::temp_directory_path() / ("turtle-report-" + std::to_string(getpid()));
    std::filesystem::create_directories(dir);
    const auto unavailable_dir = dir / "unavailable-primary";
    for (const auto* adapter : {"native-a", "native-b"}) {
        auto unavailable = header;
        unavailable["role"] = "server";
        unavailable["observation_level"] = "library-only";
        unavailable["config"]["tls"] = {{"framework_io", false}};
        unavailable["config"]["tls"]["application_bytes"] = 4;
        unavailable["config"]["channel_observer"] = false;
        unavailable["run_id"] = adapter;
        unavailable["config"]["implementation"] = adapter;
        unavailable["declaration"]["library"] = adapter;
        unavailable["connections"][0]["application_verified"] = true;
        unavailable["connections"][0]["primary_window"] = {
            {"available", false}, {"reason", "server_first_receive_not_observed"}};
        const auto folder = unavailable_dir / adapter;
        std::filesystem::create_directories(folder);
        std::ofstream raw(folder / "server.jsonl");
        raw << unavailable.dump() << '\n';
        auto unavailable_events = common_events("server", false);
        if (std::string(adapter) == "native-b")
            unavailable_events.back()["thread_cpu_ns"] = nullptr;
        for (const auto& event : unavailable_events)
            raw << event.dump() << '\n';
    }
    const auto unavailable_report = summarize(unavailable_dir, dir / "unavailable-report");
    assert(unavailable_report["invalid_samples"] == 0);
    assert(unavailable_report["groups"].size() == 2);
    assert(unavailable_report["comparisons"].empty());
    for (const auto& sample : unavailable_report["samples"]) {
        const auto& attribution = sample["connections"][0]["record_computation_attribution"];
        assert(attribution["available"] == false && attribution["segments"].is_null());
        assert(attribution["reason"] == "native_socket_io_not_observed");
    }
    for (const auto& group : unavailable_report["groups"]) {
        assert(
            group["metrics"]["handshake_call_begin_to_application_complete_elapsed_ns"]["count"] ==
            1);
        if (group["dimensions"]["library"] == "native-a")
            assert(group["metrics"]["handshake_call_begin_to_application_complete_thread_cpu_ns"]
                        ["count"] == 1);
        else
            assert(!group["metrics"].contains(
                "handshake_call_begin_to_application_complete_thread_cpu_ns"));
        assert(group["handshake_call_begin_to_application_complete"]["definition"] ==
               "handshake_call_begin_to_application_complete");
        assert(group["batches"].empty());
        assert(group["automatic_comparison_eligible"] == false);
        assert(group["dimensions"]["run_controls"]["channel_observer"] == false);
    }
    {
        std::ofstream raw(dir / "client.jsonl");
        raw << header.dump() << '\n';
        for (const auto& e : events)
            raw << e.dump() << '\n';
    }
    const auto first = summarize(dir / "client.jsonl", dir / "out");
    const auto second = summarize(dir / "client.jsonl", dir / "out");
    assert(first == second && first["groups"].size() == 1);
    assert(first["groups"][0]["metrics"]["elapsed_ns"]["stq2"] == 30);
    assert(first["groups"][0]["metrics"].contains("cycles") == false);
    assert(std::filesystem::file_size(dir / "out" / "distribution-0.svg") > 100);

    const auto fixture_root = std::filesystem::path(__FILE__).parent_path() / "fixtures";
    const auto fixture_dir = dir / "decoded-fixture";
    std::filesystem::create_directory(fixture_dir);
    std::filesystem::copy_file(fixture_root / "client.jsonl", fixture_dir / "client.jsonl");
    std::filesystem::copy_file(fixture_root / "client.decoded.json",
                               fixture_dir / "client.decoded.json");
    const auto decoded_report = summarize(fixture_dir, dir / "decoded-report");
    assert(decoded_report["samples"][0]["decoded_sidecar_status"] == "validated");
    assert(decoded_report["samples"][0]["decoded_sidecar_reason"] == "alternate_window_available");
    const auto& alternate =
        decoded_report["samples"][0]["connections"][0]["client_hello_to_finished_send"];
    assert(alternate["start_event_sequence"] == 3);
    assert(alternate["end_event_sequence"] == 8);
    assert(alternate["elapsed_ns"] == 70);
    assert(alternate["thread_cpu_ns"] == 40);
    assert(alternate["cycles"] == 80);
    assert(alternate["client_hello_bundled"] == false);
    assert(alternate["finished_bundled"] == true);
    assert(alternate["separate_plaintext_message_cpu_time_available"] == false);
    assert(decoded_report["groups"][0]["metrics"]["client_hello_to_finished_send_elapsed_ns"]
                         ["stq2"] == 70);
    assert(decoded_report["groups"][0]["client_hello_to_finished_send"]
                         ["separate_plaintext_message_cpu_time_available"] == false);
    const auto& fixture_attribution =
        decoded_report["samples"][0]["connections"][0]["record_computation_attribution"];
    assert(fixture_attribution["available"] == false &&
           fixture_attribution["reason"] == "decoded_record_mapping_unavailable" &&
           fixture_attribution["segments"].is_null());

    const auto raw_only_dir = dir / "raw-only-fixture";
    std::filesystem::create_directory(raw_only_dir);
    std::filesystem::copy_file(fixture_root / "client.jsonl", raw_only_dir / "client.jsonl");
    const auto raw_only = summarize(raw_only_dir, dir / "raw-only-report");
    assert(raw_only["samples"][0]["decoded_sidecar_status"] == "absent");
    assert(raw_only["samples"][0]["decoded_sidecar_reason"] == "optional_sidecar_not_present");
    assert(!raw_only["samples"][0]["connections"][0].contains("client_hello_to_finished_send"));
    const auto& raw_only_attribution =
        raw_only["samples"][0]["connections"][0]["record_computation_attribution"];
    assert(raw_only_attribution["available"] == false &&
           raw_only_attribution["reason"] == "decoded_sidecar_absent" &&
           raw_only_attribution["segments"].is_null());
    assert(raw_only["groups"][0]["metrics"]["elapsed_ns"] ==
           decoded_report["groups"][0]["metrics"]["elapsed_ns"]);

    auto rejected_sidecar = [&](const std::string& name, const std::string& reason, auto mutate) {
        const auto rejected_dir = dir / name;
        std::filesystem::create_directory(rejected_dir);
        std::filesystem::copy_file(fixture_root / "client.jsonl", rejected_dir / "client.jsonl");
        std::ifstream decoded_fixture(fixture_root / "client.decoded.json");
        auto decoded = J::parse(decoded_fixture);
        mutate(decoded);
        std::ofstream(rejected_dir / "client.decoded.json") << decoded.dump(2) << '\n';
        const auto report = summarize(rejected_dir, dir / (name + "-report"));
        assert(report["samples"][0]["decoded_sidecar_status"] == "ignored");
        assert(report["samples"][0]["decoded_sidecar_reason"] == reason);
        assert(!report["samples"][0]["connections"][0].contains("client_hello_to_finished_send"));
        const auto& attribution =
            report["samples"][0]["connections"][0]["record_computation_attribution"];
        assert(attribution["available"] == false && attribution["segments"].is_null());
        assert(attribution["reason"] == "decoded_sidecar_" + reason);
    };
    rejected_sidecar("mismatched-sample", "sample_mismatch",
                     [](J& decoded) { decoded["sample"] = 999; });
    rejected_sidecar("mismatched-role", "role_mismatch",
                     [](J& decoded) { decoded["role"] = "server"; });
    rejected_sidecar("mismatched-connection", "connection_set_mismatch",
                     [](J& decoded) { decoded["connections"][0]["connection"] = 1; });
    rejected_sidecar("incomplete-decode", "decryption_incomplete",
                     [](J& decoded) { decoded["connections"][0]["decryption_complete"] = false; });
    const auto malformed_dir = dir / "malformed-sidecar";
    std::filesystem::create_directory(malformed_dir);
    std::filesystem::copy_file(fixture_root / "client.jsonl", malformed_dir / "client.jsonl");
    std::ofstream(malformed_dir / "client.decoded.json") << "{broken\n";
    const auto malformed = summarize(malformed_dir, dir / "malformed-report");
    assert(malformed["samples"][0]["decoded_sidecar_status"] == "ignored");
    assert(malformed["samples"][0]["decoded_sidecar_reason"] == "malformed_json");
    assert(malformed["samples"][0]["connections"][0]["record_computation_attribution"]["reason"] ==
           "decoded_sidecar_malformed_json");
    const auto separated_dir = dir / "separate-conditions";
    std::filesystem::create_directory(separated_dir);
    for (int i = -1; i < 4; ++i) {
        auto alternate = header;
        alternate["run_id"] = "separated-" + std::to_string(i);
        if (i == 0)
            alternate["config"]["implementation"] = "different_implementation";
        if (i == 1)
            alternate["pinned_cpu"] = 3;
        if (i == 2)
            alternate["config"]["perf"] = true;
        if (i == 3)
            alternate["declaration"]["build_options"] = "different_build";
        auto folder = separated_dir / std::to_string(i);
        std::filesystem::create_directory(folder);
        std::ofstream raw(folder / "client.jsonl");
        raw << alternate.dump() << '\n';
        for (const auto& e : events)
            raw << e.dump() << '\n';
    }
    const auto separated = summarize(separated_dir, dir / "grouped");
    assert(separated["groups"].size() >= 5);

    const auto candidates_dir = dir / "comparison-candidates";
    std::filesystem::create_directory(candidates_dir);
    const J socket = {{"nonblocking", true},
                      {"tcp_nodelay", true},
                      {"send_buffer", 131072},
                      {"receive_buffer", 131072},
                      {"kernel_timestamps", false}};
    auto write_candidate = [&](const std::filesystem::path& root, const std::string& folder_name,
                               const std::string& own_adapter, const std::string& peer_adapter,
                               const std::string& profile, const std::string& library,
                               std::uint64_t batch = 1, int peer_cpu = 8,
                               const std::string& peer_version = "peer-version",
                               bool include_peer = true, int own_contract_revision = 3,
                               int peer_contract_revision = 3) {
        auto candidate = header;
        if (own_contract_revision > 0)
            candidate["measurement_contract_revision"] = own_contract_revision;
        else
            candidate.erase("measurement_contract_revision");
        candidate["batch"] = batch;
        candidate["run_id"] = (root / folder_name).string();
        candidate["config"]["implementation"] = own_adapter;
        candidate["profile_hash"] = profile;
        candidate["pinned_cpu"] = 6;
        candidate["config"]["perf"] = false;
        candidate["config"]["perf_scope"] = "user";
        candidate["capabilities"] = {{"perf", false},
                                     {"affinity", true},
                                     {"perf_requested_scope", "user"},
                                     {"perf_status", "disabled"},
                                     {"perf_effective_scope", nullptr},
                                     {"perf_failure_stage", "fixture-stage"},
                                     {"perf_error_number", 100 + batch},
                                     {"perf_note", library + " diagnostic"}};
        candidate["declaration"]["library"] = library;
        candidate["declaration"]["version"] = library + "-version";
        candidate["declaration"]["build_options"] = library + "-build";
        candidate["loaded_context_size"] = 0;
        candidate["loaded_context_hash"] = "";
        candidate["connections"][0]["socket"] = socket;
        if (own_contract_revision >= 3) {
            candidate["connections"][0]["end_sequence"] = events.size();
            candidate["connections"][0]["scenario_completed"] = true;
        }
        const auto folder = root / folder_name;
        std::filesystem::create_directory(folder);
        std::ofstream raw(folder / "client.jsonl");
        raw << candidate.dump() << '\n';
        std::size_t sequence = 0;
        for (auto event : events) {
            event["sequence"] = ++sequence;
            raw << event.dump() << '\n';
        }
        raw.close();
        if (include_peer) {
            auto peer = candidate;
            peer["role"] = "server";
            peer["config"]["implementation"] = peer_adapter;
            peer["pinned_cpu"] = peer_cpu;
            peer["declaration"]["library"] = "peer-library";
            peer["declaration"]["version"] = peer_version;
            peer["declaration"]["build_options"] = "peer-build";
            if (peer_contract_revision > 0)
                peer["measurement_contract_revision"] = peer_contract_revision;
            else
                peer.erase("measurement_contract_revision");
            std::ofstream peer_file(folder / "server.jsonl");
            peer_file << peer.dump() << '\n';
            for (auto event : events) {
                if (event["kind"] == "IO_SEND_ENTER")
                    event["kind"] = "IO_RECV_ENTER";
                else if (event["kind"] == "IO_SEND_RETURN") {
                    event["kind"] = "IO_RECV_RETURN";
                    event["transferred"] = 1;
                }
                if (event["call"] == "app_recv")
                    event["call"] = "app_send";
                peer_file << event.dump() << '\n';
            }
        }
    };
    write_candidate(candidates_dir, "a", "adapter-a", "fixed-peer", "same-profile", "library-a");
    write_candidate(candidates_dir, "b", "adapter-b", "fixed-peer", "same-profile", "library-b");
    write_candidate(candidates_dir, "different-peer", "adapter-c", "other-peer", "same-profile",
                    "library-c");
    write_candidate(candidates_dir, "different-profile", "adapter-d", "fixed-peer", "other-profile",
                    "library-d");
    write_candidate(candidates_dir, "different-peer-cpu", "adapter-e", "fixed-peer", "same-profile",
                    "library-e", 1, 10);
    write_candidate(candidates_dir, "different-peer-version", "adapter-f", "fixed-peer",
                    "same-profile", "library-f", 1, 8, "other-peer-version");
    write_candidate(candidates_dir, "missing-peer", "adapter-g", "fixed-peer", "same-profile",
                    "library-g", 1, 8, "peer-version", false);
    write_candidate(candidates_dir, "missing-peer-two", "adapter-h", "fixed-peer", "same-profile",
                    "library-h", 1, 8, "peer-version", false);
    const auto candidates = client_report(candidates_dir, dir / "candidate-report");
    assert(candidates["groups"].size() == 8);
    std::map<std::string, J> candidate_dimensions;
    for (const auto& group : candidates["groups"]) {
        const auto& dimensions = group["dimensions"];
        candidate_dimensions.emplace(dimensions["client_adapter"].get<std::string>(), dimensions);
    }
    assert(candidate_dimensions.at("adapter-a")["peer_pinned_cpu"] == 8);
    assert(candidate_dimensions.at("adapter-a")["peer_library_version"] == "peer-version");
    assert(candidate_dimensions.at("adapter-e")["peer_pinned_cpu"] == 10);
    assert(candidate_dimensions.at("adapter-f")["peer_library_version"] == "other-peer-version");
    assert(candidate_dimensions.at("adapter-g")["peer_verified"] == false);
    assert(candidate_dimensions.at("adapter-a")["run_controls"]["perf_scope"] == "user");
    assert(candidate_dimensions.at("adapter-a")["perf_support"] ==
           J({{"perf_requested_scope", "user"},
              {"perf_status", "disabled"},
              {"perf_effective_scope", nullptr}}));
    assert(candidate_dimensions.at("adapter-a")["peer_run_controls"]["perf_scope"] == "user");
    assert(candidate_dimensions.at("adapter-a")["peer_perf_support"]["perf_status"] == "disabled");
    assert(!candidate_dimensions.at("adapter-a")["peer_capabilities"].contains("perf_note"));
    assert(
        !candidate_dimensions.at("adapter-a")["peer_capabilities"].contains("perf_failure_stage"));
    assert(candidates["comparisons"].size() == 1);
    assert(candidates["comparisons"][0]["method"] == "independent_percentile_bootstrap");
    assert(candidates["comparisons"][0]["interpretation"] ==
           "exploratory_adapter_candidate_not_equivalence");
    assert(candidates["comparisons"][0]["eligibility"] ==
           "same_conditions_verified_fixed_peer_and_batch_ids_except_measured_adapter_identity");

    const auto contract_dir = dir / "measurement-contract-candidates";
    std::filesystem::create_directory(contract_dir);
    write_candidate(contract_dir, "current-a", "current-a", "fixed-peer", "same-profile",
                    "current-a");
    write_candidate(contract_dir, "current-b", "current-b", "fixed-peer", "same-profile",
                    "current-b");
    auto rewrite_first_header = [](const std::filesystem::path& path, auto change) {
        std::ifstream input(path);
        std::string first;
        std::getline(input, first);
        const std::string rest{std::istreambuf_iterator<char>(input),
                               std::istreambuf_iterator<char>()};
        auto metadata = J::parse(first);
        change(metadata);
        std::ofstream(path) << metadata.dump() << '\n' << rest;
    };
    for (int schema : {1, 2}) {
        const auto obsolete = dir / ("unsupported-schema-" + std::to_string(schema));
        std::filesystem::create_directory(obsolete);
        write_candidate(obsolete, "sample", "own", "peer", "profile", "library");
        rewrite_first_header(obsolete / "sample/client.jsonl", [=](J& h) { h["schema"] = schema; });
        bool rejected = false;
        try {
            client_report(obsolete, obsolete / "report");
        } catch (const std::runtime_error& e) {
            rejected = std::string(e.what()).find("requires schema 3") != std::string::npos;
        }
        assert(rejected);
    }
    // External sampling changes timing even when the raw event mode is timing.
    // The peer can perturb completion time too; either endpoint excludes the pair.
    for (const auto* profiled_role : {"client", "server"}) {
        const auto profiled_dir = dir / (std::string("cpu-profile-") + profiled_role);
        std::filesystem::create_directory(profiled_dir);
        for (const auto* name : {"first", "second"}) {
            write_candidate(profiled_dir, name, name, "fixed-peer", "same-profile", name);
            rewrite_first_header(profiled_dir / name / (std::string(profiled_role) + ".jsonl"),
                                 [](J& metadata) { metadata["config"]["cpu_profile"] = true; });
        }
        const auto profiled = client_report(profiled_dir, profiled_dir / "report", true);
        assert(profiled["groups"].size() == 2);
        assert(profiled["comparisons"].empty());
        for (const auto& group : profiled["groups"]) {
            assert(group["dimensions"]["timing_interpretation"] == "diagnostic_only");
            assert(group["automatic_comparison_eligible"] == false);
            assert(std::find(group["comparison_exclusion_reasons"].begin(),
                             group["comparison_exclusion_reasons"].end(),
                             "cpu_profile_diagnostic_only") !=
                   group["comparison_exclusion_reasons"].end());
            assert(group["metrics"]["elapsed_ns"]["count"] == 1);
        }
        std::ifstream repeated_file(profiled_dir / "report/repeated-context-summary.json");
        const auto repeated = J::parse(repeated_file);
        assert(repeated["comparisons"].empty());
    }
    write_candidate(contract_dir, "missing-perf", "missing-perf", "fixed-peer", "same-profile",
                    "missing-perf");
    rewrite_first_header(contract_dir / "missing-perf" / "client.jsonl", [](J& metadata) {
        metadata["config"].erase("perf_scope");
        metadata["capabilities"].erase("perf_requested_scope");
        metadata["capabilities"].erase("perf_status");
        metadata["capabilities"].erase("perf_effective_scope");
    });
    write_candidate(contract_dir, "missing-effective-own", "missing-effective-own", "fixed-peer",
                    "same-profile", "missing-effective-own");
    rewrite_first_header(contract_dir / "missing-effective-own" / "client.jsonl", [](J& metadata) {
        metadata["capabilities"].erase("perf_effective_scope");
    });
    write_candidate(contract_dir, "missing-effective-peer", "missing-effective-peer", "fixed-peer",
                    "same-profile", "missing-effective-peer");
    rewrite_first_header(contract_dir / "missing-effective-peer" / "server.jsonl", [](J& metadata) {
        metadata["capabilities"].erase("perf_effective_scope");
    });
    // Measured implementation provenance separates groups but must not suppress
    // fixed-peer comparisons of two implementations of the same technique.
    const auto provenance_dir = dir / "provenance-candidates";
    std::filesystem::create_directories(provenance_dir);
    for (const auto* name : {"one", "two", "other-peer"}) {
        write_candidate(provenance_dir, name, name, "fixed-peer", "same-profile", name, 1, 8,
                        "peer-version", true, 3, 3);
        for (const auto* role : {"client", "server"}) {
            rewrite_first_header(
                provenance_dir / name / (std::string(role) + ".jsonl"), [&](J& metadata) {
                    metadata["schema"] = 3;
                    metadata["config"]["tls"] = {{"scenario", "client-request"},
                                                 {"application_bytes", 4}};
                    const bool measured = std::string(role) == "client";
                    const std::string source = measured                            ? name
                                               : std::string(name) == "other-peer" ? "different"
                                                                                   : "fixed";
                    metadata["declaration"]["source_version"] = source;
                    metadata["declaration"]["patch_hash"] = source;
                    metadata["declaration"]["implementation"] = "baseline";
                    metadata["declaration"]["technique"] = "standard-tls13";
                });
        }
    }
    const auto provenance = client_report(provenance_dir, dir / "provenance-report");
    assert(provenance["groups"].size() == 3);
    assert(provenance["comparisons"].size() == 1);
    const auto contracts = client_report(contract_dir, dir / "measurement-contract-report");
    assert(contracts["groups"].size() == 5);
    assert(contracts["comparisons"].size() == 1);
    for (const auto& group : contracts["groups"]) {
        const auto adapter = group["dimensions"]["client_adapter"].get<std::string>();
        assert(group["metrics"]["elapsed_ns"]["count"] == 1);
        if (adapter == "missing-perf") {
            assert(group["metrics"]["elapsed_ns"]["count"] == 1);
            assert(group["automatic_comparison_eligible"] == false);
            assert(std::find(group["comparison_exclusion_reasons"].begin(),
                             group["comparison_exclusion_reasons"].end(),
                             "perf_condition_unknown") !=
                   group["comparison_exclusion_reasons"].end());
        } else if (adapter == "missing-effective-own") {
            assert(!group["dimensions"]["perf_support"].contains("perf_effective_scope"));
            assert(group["metrics"]["elapsed_ns"]["count"] == 1);
            assert(group["automatic_comparison_eligible"] == false);
            assert(std::find(group["comparison_exclusion_reasons"].begin(),
                             group["comparison_exclusion_reasons"].end(),
                             "perf_condition_unknown") !=
                   group["comparison_exclusion_reasons"].end());
        } else if (adapter == "missing-effective-peer") {
            assert(!group["dimensions"]["peer_perf_support"].contains("perf_effective_scope"));
            assert(group["metrics"]["elapsed_ns"]["count"] == 1);
            assert(group["automatic_comparison_eligible"] == false);
            assert(std::find(group["comparison_exclusion_reasons"].begin(),
                             group["comparison_exclusion_reasons"].end(),
                             "peer_perf_condition_unknown") !=
                   group["comparison_exclusion_reasons"].end());
        }
    }

    const auto unsupported_dir = dir / "unsupported-perf-candidates";
    std::filesystem::create_directory(unsupported_dir);
    for (const auto* name : {"first", "second"}) {
        write_candidate(unsupported_dir, name, std::string("adapter-") + name, "fixed-peer",
                        "same-profile", std::string("library-") + name);
        for (const auto* role : {"client", "server"})
            rewrite_first_header(
                unsupported_dir / name / (std::string(role) + ".jsonl"), [name](J& metadata) {
                    metadata["config"]["perf"] = true;
                    metadata["capabilities"]["perf_status"] = "unsupported";
                    metadata["capabilities"]["perf_note"] = std::string("dynamic ") + name;
                    metadata["capabilities"]["perf_error_number"] =
                        std::string(name) == "first" ? 1 : 13;
                });
    }
    const auto unsupported = client_report(unsupported_dir, dir / "unsupported-perf-report");
    assert(unsupported["comparisons"].size() == 1);
    rewrite_first_header(unsupported_dir / "first" / "client.jsonl", [](J& metadata) {
        metadata["capabilities"].erase("perf_effective_scope");
    });
    const auto unsupported_missing_own =
        client_report(unsupported_dir, dir / "unsupported-missing-own-report");
    assert(unsupported_missing_own["comparisons"].empty());
    for (const auto& group : unsupported_missing_own["groups"])
        if (group["dimensions"]["client_adapter"] == "adapter-first") {
            assert(!group["dimensions"]["perf_support"].contains("perf_effective_scope"));
            assert(group["metrics"]["elapsed_ns"]["count"] == 1);
            assert(group["automatic_comparison_eligible"] == false);
        }
    rewrite_first_header(unsupported_dir / "first" / "client.jsonl", [](J& metadata) {
        metadata["capabilities"]["perf_effective_scope"] = nullptr;
    });
    rewrite_first_header(unsupported_dir / "second" / "server.jsonl", [](J& metadata) {
        metadata["capabilities"].erase("perf_effective_scope");
    });
    const auto unsupported_missing_peer =
        client_report(unsupported_dir, dir / "unsupported-missing-peer-report");
    assert(unsupported_missing_peer["comparisons"].empty());
    for (const auto& group : unsupported_missing_peer["groups"])
        if (group["dimensions"]["client_adapter"] == "adapter-second") {
            assert(!group["dimensions"]["peer_perf_support"].contains("perf_effective_scope"));
            assert(group["metrics"]["elapsed_ns"]["count"] == 1);
            assert(group["automatic_comparison_eligible"] == false);
        }

    for (const auto* status : {"disabled", "unsupported"})
        for (const auto* missing_side : {"own", "peer"}) {
            const auto pair_dir =
                dir / (std::string("perf-presence-") + status + "-" + missing_side);
            std::filesystem::create_directory(pair_dir);
            for (const auto* name : {"known", "missing"}) {
                write_candidate(pair_dir, name, "same-adapter", "fixed-peer", "same-profile",
                                "same-library");
                if (std::string(status) == "unsupported")
                    for (const auto* role : {"client", "server"})
                        rewrite_first_header(
                            pair_dir / name / (std::string(role) + ".jsonl"), [](J& metadata) {
                                metadata["config"]["perf"] = true;
                                metadata["capabilities"]["perf_status"] = "unsupported";
                            });
            }
            rewrite_first_header(
                pair_dir / "missing" /
                    (std::string(missing_side) == "own" ? "client.jsonl" : "server.jsonl"),
                [](J& metadata) { metadata["capabilities"].erase("perf_effective_scope"); });
            const auto pair_report =
                client_report(pair_dir, dir / (std::string("perf-presence-report-") + status + "-" +
                                           missing_side));
            assert(pair_report["groups"].size() == 2);
            assert(pair_report["comparisons"].empty());
            bool known_group = false;
            bool missing_group = false;
            const char* support_name =
                std::string(missing_side) == "own" ? "perf_support" : "peer_perf_support";
            for (const auto& group : pair_report["groups"]) {
                const auto& support = group["dimensions"][support_name];
                assert(group["metrics"]["elapsed_ns"]["count"] == 1);
                assert(group["metrics"]["thread_cpu_ns"]["count"] == 1);
                if (support.contains("perf_effective_scope")) {
                    known_group = group["automatic_comparison_eligible"] == true;
                } else {
                    missing_group = group["automatic_comparison_eligible"] == false;
                }
            }
            assert(known_group && missing_group);
        }

    const auto scope_dir = dir / "perf-scope-candidates";
    std::filesystem::create_directory(scope_dir);
    write_candidate(scope_dir, "user", "adapter-user", "fixed-peer", "same-profile",
                    "library-user");
    write_candidate(scope_dir, "kernel", "adapter-kernel", "fixed-peer", "same-profile",
                    "library-kernel");
    for (const auto* role : {"client", "server"}) {
        rewrite_first_header(scope_dir / "user" / (std::string(role) + ".jsonl"), [](J& metadata) {
            metadata["config"]["perf"] = true;
            metadata["capabilities"]["perf"] = true;
            metadata["capabilities"]["perf_status"] = "available";
            metadata["capabilities"]["perf_effective_scope"] = "user";
        });
        rewrite_first_header(scope_dir / "kernel" / (std::string(role) + ".jsonl"),
                             [](J& metadata) {
                                 metadata["config"]["perf"] = true;
                                 metadata["config"]["perf_scope"] = "user+kernel";
                                 metadata["capabilities"]["perf"] = true;
                                 metadata["capabilities"]["perf_requested_scope"] = "user+kernel";
                                 metadata["capabilities"]["perf_status"] = "available";
                                 metadata["capabilities"]["perf_effective_scope"] = "user+kernel";
                             });
    }
    const auto scopes = client_report(scope_dir, dir / "perf-scope-report");
    assert(scopes["groups"].size() == 2 && scopes["comparisons"].empty());

    const auto peer_perf_dir = dir / "peer-perf-candidates";
    std::filesystem::create_directory(peer_perf_dir);
    write_candidate(peer_perf_dir, "first", "adapter-first", "fixed-peer", "same-profile",
                    "library-first");
    write_candidate(peer_perf_dir, "second", "adapter-second", "fixed-peer", "same-profile",
                    "library-second");
    rewrite_first_header(peer_perf_dir / "second" / "server.jsonl", [](J& metadata) {
        metadata["config"]["perf"] = true;
        metadata["capabilities"]["perf_status"] = "unsupported";
    });
    const auto peer_perf = client_report(peer_perf_dir, dir / "peer-perf-report");
    assert(peer_perf["groups"].size() == 2 && peer_perf["comparisons"].empty());

    const auto disjoint_dir = dir / "disjoint-batches";
    std::filesystem::create_directory(disjoint_dir);
    write_candidate(disjoint_dir, "batch-one", "adapter-one", "fixed-peer", "same-profile",
                    "library-one", 1);
    write_candidate(disjoint_dir, "batch-two", "adapter-two", "fixed-peer", "same-profile",
                    "library-two", 2);
    const auto disjoint = client_report(disjoint_dir, dir / "disjoint-report");
    assert(disjoint["comparisons"].empty());

    auto update_header = [&](const std::filesystem::path& path, auto change) {
        std::ifstream input(path);
        std::string line;
        std::getline(input, line);
        auto metadata = J::parse(line);
        const std::string rest{std::istreambuf_iterator<char>(input),
                               std::istreambuf_iterator<char>()};
        input.close();
        change(metadata);
        std::ofstream(path) << metadata.dump() << '\n' << rest;
    };
    const auto sockets_dir = dir / "socket-settings";
    std::filesystem::create_directory(sockets_dir);
    for (const auto* folder : {"first", "second"}) {
        write_candidate(sockets_dir, folder, "same-adapter", "fixed-peer", "same-profile",
                        "same-library");
        for (const auto* role : {"client", "server"})
            update_header(sockets_dir / folder / (std::string(role) + ".jsonl"),
                          [&](J& metadata) { metadata["connections"][0]["socket"] = socket; });
    }
    update_header(sockets_dir / "second/client.jsonl", [](J& metadata) {
        metadata["connections"][0]["socket"]["send_buffer"] = 262144;
    });
    assert(client_report(sockets_dir, dir / "socket-report")["groups"].size() == 2);
    update_header(sockets_dir / "second/client.jsonl",
                  [&](J& metadata) { metadata["connections"][0]["socket"] = socket; });
    update_header(sockets_dir / "second/server.jsonl", [](J& metadata) {
        metadata["connections"][0]["socket"]["receive_buffer"] = 262144;
    });
    assert(client_report(sockets_dir, dir / "peer-socket-report")["groups"].size() == 2);

    const auto warmup_sockets_dir = dir / "warmup-socket-settings";
    std::filesystem::create_directory(warmup_sockets_dir);
    for (const auto* folder : {"first", "second"}) {
        write_candidate(warmup_sockets_dir, folder, "same-adapter", "fixed-peer", "same-profile",
                        "same-library");
        for (const auto* role : {"client", "server"})
            update_header(warmup_sockets_dir / folder / (std::string(role) + ".jsonl"),
                          [&](J& metadata) {
                              metadata["config"]["warmups"] = 1;
                              metadata["connections"].push_back(
                                  {{"index", 1}, {"warmup", true}, {"socket", socket}});
                          });
    }
    update_header(warmup_sockets_dir / "second/client.jsonl", [](J& metadata) {
        metadata["connections"][1]["socket"]["send_buffer"] = 262144;
    });
    const auto warmup_sockets = client_report(warmup_sockets_dir, dir / "warmup-socket-report");
    assert(warmup_sockets["groups"].size() == 2);
    assert(warmup_sockets["comparisons"].empty());
    for (const auto& group : warmup_sockets["groups"]) {
        assert(group["dimensions"]["socket_settings"].size() == 2);
        assert(group["metrics"]["elapsed_ns"]["count"] == 1);
    }

    const auto missing_warmup_socket_dir = dir / "missing-warmup-socket";
    std::filesystem::create_directory(missing_warmup_socket_dir);
    write_candidate(missing_warmup_socket_dir, "complete", "adapter-a", "fixed-peer",
                    "same-profile", "library-a");
    write_candidate(missing_warmup_socket_dir, "missing", "adapter-b", "fixed-peer", "same-profile",
                    "library-b");
    for (const auto* folder : {"complete", "missing"})
        for (const auto* role : {"client", "server"})
            update_header(missing_warmup_socket_dir / folder / (std::string(role) + ".jsonl"),
                          [&](J& metadata) {
                              metadata["config"]["warmups"] = 1;
                              metadata["connections"].push_back(
                                  {{"index", 1}, {"warmup", true}, {"socket", socket}});
                          });
    update_header(missing_warmup_socket_dir / "missing/client.jsonl",
                  [](J& metadata) { metadata["connections"][1].erase("socket"); });
    const auto missing_warmup_socket =
        client_report(missing_warmup_socket_dir, dir / "missing-warmup-socket-report");
    assert(missing_warmup_socket["groups"].size() == 2);
    assert(missing_warmup_socket["comparisons"].empty());
    bool missing_identity_observed = false;
    for (const auto& group : missing_warmup_socket["groups"]) {
        const auto& settings = group["dimensions"]["socket_settings"];
        assert(settings.size() == 2);
        missing_identity_observed = missing_identity_observed || settings[1].is_null();
    }
    assert(missing_identity_observed);

    const auto pure_netem_dir = dir / "pure-tls-netem";
    std::filesystem::create_directory(pure_netem_dir);
    auto write_network_run = [&](const char* name, int delay_ms) {
        const auto run = pure_netem_dir / name;
        std::filesystem::create_directory(run);
        write_candidate(run, "sample-1", "same-adapter", "fixed-peer", "same-profile",
                        "same-library");
        for (const auto* role : {"client", "server"})
            update_header(run / "sample-1" / (std::string(role) + ".jsonl"), [&](J& metadata) {
                metadata["config"]["network_handoff"] = J::object();
                metadata["config"]["network_handoff"]["net_profile"] = {
                    {"paths",
                     {{"tls_c2s", {{"delay_ms", delay_ms}}},
                      {"tls_s2c", {{"delay_ms", delay_ms}}}}}};
            });
        const J observation_ids = J::array({"1:setup:begin", "1:setup:end", "1:scenario:begin",
                                            "1:scenario:end", "1:cleanup:begin", "1:cleanup:end"});
        {
            std::ofstream ledger(run / "attempts.jsonl");
            ledger << J({{"type", "turtle-attempt-ledger"},
                         {"schema", 1},
                         {"record_kind", "run_config"},
                         {"requested_count", 1}})
                          .dump()
                   << '\n';
            ledger << J({{"type", "turtle-attempt-ledger"},
                         {"schema", 1},
                         {"record_kind", "attempt_started"},
                         {"attempt_id", 1},
                         {"started", true},
                         {"final_status", "not_attempted"},
                         {"network_observation_ids", J::array()}})
                          .dump()
                   << '\n';
            ledger << J({{"type", "turtle-attempt-ledger"},
                         {"schema", 1},
                         {"record_kind", "attempt_final"},
                         {"attempt_id", 1},
                         {"final_status", "success"},
                         {"network_observation_ids", observation_ids}})
                          .dump()
                   << '\n';
            ledger << J({{"type", "turtle-attempt-ledger"},
                         {"schema", 1},
                         {"record_kind", "run_summary"},
                         {"requested", 1},
                         {"started", 1},
                         {"success", 1},
                         {"timeout", 0},
                         {"error", 0},
                         {"incomplete", 0},
                         {"not_attempted", 0},
                         {"missing_artifacts", 0},
                         {"missing_artifact_rows", J::array()}})
                          .dump()
                   << '\n';
        }
        const J paths = {
            {"tls_c2s", {{"delay_ms", delay_ms}, {"loss_percent", 0.0}, {"limit_packets", 10000}}},
            {"tls_s2c", {{"delay_ms", delay_ms}, {"loss_percent", 0.0}, {"limit_packets", 10000}}}};
        const J actual_paths = {{"tls_c2s",
                                 {{"interface", "rstls"},
                                  {"kind", "netem"},
                                  {"delay_ms", delay_ms},
                                  {"loss_percent", 0.0},
                                  {"limit_packets", 10000}}},
                                {"tls_s2c",
                                 {{"interface", "rctls"},
                                  {"kind", "netem"},
                                  {"delay_ms", delay_ms},
                                  {"loss_percent", 0.0},
                                  {"limit_packets", 10000}}}};
        const J readbacks = {
            {"tls_c2s",
             {{"interface", "rstls"}, {"requested", paths.at("tls_c2s")}, {"root_kind", "netem"}}},
            {"tls_s2c",
             {{"interface", "rctls"}, {"requested", paths.at("tls_s2c")}, {"root_kind", "netem"}}}};
        std::ofstream(run / "network-provenance.json")
            << J({{"type", "turtle-network-provenance"},
                  {"schema", 2},
                  {"status", "complete"},
                  {"runner", {{"returncode", 0}}},
                  {"host_network_identity",
                   {{"unchanged", true},
                    {"before", {{"supported", true}}},
                    {"after", {{"supported", true}}}}},
                  {"lifecycle", {{"namespace_fds_closed", true}, {"owned_pipe_fds_closed", true}}},
                  {"cleanup", J::array({{{"helper", "client"}, {"result", "reaped"}},
                                        {{"helper", "server"}, {"result", "reaped"}},
                                        {{"helper", "router"}, {"result", "reaped"}}})},
                  {"finished_monotonic_ns", 1000},
                  {"applied_qdisc_readback", readbacks},
                  {"condition_identity",
                   {{"topology",
                     {{"kind", "three-netns-receiver-facing-router-egress"},
                      {"addresses", {{"client_tls", "10.203.1.2"}, {"server", "10.203.2.2"}}},
                      {"interfaces",
                       {{"client_tls", "ctls"},
                        {"server", "stls"},
                        {"router_client_tls", "rctls"},
                        {"router_server", "rstls"}}}}},
                    {"requested", {{"qdisc", "netem"}, {"paths", paths}}},
                    {"actual", {{"qdisc", "netem"}, {"paths", actual_paths}}},
                    {"mtu", {{"requested", 1500}, {"actual", {{"ctls", 1500}}}}},
                    {"offload", {{"requested", false}, {"actual", {{"ctls", false}}}}},
                    {"trace", {{"requested", false}}}}}})
                   .dump(2)
            << '\n';
        std::ofstream observations(run / "network-observations.jsonl");
        for (const auto& id : observation_ids) {
            const auto text = id.get<std::string>();
            const auto phase = text.find(":setup:") != std::string::npos     ? "setup"
                               : text.find(":cleanup:") != std::string::npos ? "cleanup"
                                                                             : "scenario";
            observations << J({{"type", "network-observation"},
                               {"schema", 1},
                               {"observation_id", text},
                               {"attempt", 1},
                               {"phase", phase},
                               {"edge", text.ends_with("begin") ? "begin" : "end"},
                               {"qdiscs", readbacks}})
                                .dump()
                         << '\n';
        }
    };
    write_network_run("zero", 0);
    write_network_run("twenty", 20);
    const auto pure_netem = client_report(pure_netem_dir, dir / "pure-netem-report");
    assert(pure_netem["groups"].size() == 2);
    assert(pure_netem["comparisons"].empty());
    assert(!pure_netem.contains("lookup_summary"));
    assert(!std::filesystem::exists(dir / "pure-netem-report" / "lookup-summary.json"));
    J zero_dimensions;
    for (const auto& group : pure_netem["groups"]) {
        const auto& dimensions = group["dimensions"];
        assert(dimensions["network_actual_identity"]["topology"]["kind"] ==
               "three-netns-receiver-facing-router-egress");
        assert(dimensions["automatic_comparison_identity_complete"] == true);
        assert(group["automatic_comparison_eligible"] == true);
        if (dimensions["network_actual_identity"]["actual"]["paths"]["tls_c2s"]["delay_ms"] == 0)
            zero_dimensions = dimensions;
    }
    const auto zero_observations_path = pure_netem_dir / "zero" / "network-observations.jsonl";
    std::ifstream zero_observations_input(zero_observations_path);
    const std::string zero_observations{std::istreambuf_iterator<char>(zero_observations_input),
                                        std::istreambuf_iterator<char>()};
    auto rewrite_observations = [&](auto change) {
        std::istringstream input(zero_observations);
        std::ofstream output(zero_observations_path);
        std::string line;
        while (std::getline(input, line)) {
            auto row = J::parse(line);
            change(row);
            output << row.dump() << '\n';
        }
    };
    auto require_network_payload_failure = [&](const char* output_name) {
        const auto failed = client_report(pure_netem_dir / "zero", dir / output_name);
        assert(failed["groups"].size() == 1);
        assert(failed["groups"][0]["dimensions"] == zero_dimensions);
        assert(failed["groups"][0]["automatic_comparison_eligible"] == false);
        assert(failed["groups"][0]["metrics"].empty());
        assert(failed["comparisons"].empty());
        assert(failed["samples"][0]["network_integrity"]["eligible"] == false);
    };
    rewrite_observations([](J& row) { row.erase("qdiscs"); });
    require_network_payload_failure("missing-qdiscs-report");
    rewrite_observations([](J& row) { row["qdiscs"] = J::object(); });
    require_network_payload_failure("empty-qdiscs-report");
    std::ofstream(zero_observations_path) << zero_observations;

    const auto zero_provenance_path = pure_netem_dir / "zero" / "network-provenance.json";
    const auto zero_provenance = J::parse(std::ifstream(zero_provenance_path));
    auto trace_provenance = zero_provenance;
    trace_provenance["condition_identity"]["trace"]["requested"] = true;
    trace_provenance["cleanup"].push_back({{"observer", "reaped"}});
    std::ofstream(zero_provenance_path) << trace_provenance.dump(2) << '\n';
    rewrite_observations([](J& row) { row["packet_trace"] = "packets.jsonl"; });
    const auto trace_complete = client_report(pure_netem_dir / "zero", dir / "trace-complete-report");
    assert(trace_complete["groups"][0]["automatic_comparison_eligible"] == true);
    const auto trace_dimensions = trace_complete["groups"][0]["dimensions"];
    rewrite_observations([](J& row) { row.erase("packet_trace"); });
    const auto trace_missing = client_report(pure_netem_dir / "zero", dir / "trace-missing-report");
    assert(trace_missing["groups"][0]["dimensions"] == trace_dimensions);
    assert(trace_missing["groups"][0]["automatic_comparison_eligible"] == false);
    assert(trace_missing["groups"][0]["metrics"].empty());
    assert(trace_missing["comparisons"].empty());
    assert(trace_missing["samples"][0]["network_integrity"]["eligible"] == false);
    rewrite_observations([](J& row) { row["packet_trace"] = nullptr; });
    const auto trace_null = client_report(pure_netem_dir / "zero", dir / "trace-null-report");
    assert(trace_null["groups"][0]["dimensions"] == trace_dimensions);
    assert(trace_null["groups"][0]["automatic_comparison_eligible"] == false);
    assert(trace_null["groups"][0]["metrics"].empty());
    assert(trace_null["comparisons"].empty());
    assert(trace_null["samples"][0]["network_integrity"]["eligible"] == false);
    std::ofstream(zero_observations_path) << zero_observations;
    std::ofstream(zero_provenance_path) << zero_provenance.dump(2) << '\n';

    auto none_provenance = zero_provenance;
    none_provenance["condition_identity"]["requested"]["qdisc"] = "none";
    none_provenance["condition_identity"]["actual"]["qdisc"] = "none";
    for (const auto* path : {"tls_c2s", "tls_s2c"}) {
        auto& actual = none_provenance["condition_identity"]["actual"]["paths"][path];
        actual["kind"] = "noqueue";
        actual["limit_packets"] = nullptr;
        none_provenance["applied_qdisc_readback"][path]["root_kind"] = "noqueue";
    }
    std::ofstream(zero_provenance_path) << none_provenance.dump(2) << '\n';
    const auto none_qdisc = client_report(pure_netem_dir / "zero", dir / "none-qdisc-report");
    assert(none_qdisc["groups"][0]["automatic_comparison_eligible"] == true);
    assert(!none_qdisc["groups"][0]["metrics"].empty());
    assert(none_qdisc["groups"][0]["dimensions"]["network_actual_identity"]["actual"]["paths"]
                     ["tls_c2s"]["limit_packets"]
                         .is_null());

    auto missing_limit = none_provenance;
    missing_limit["condition_identity"]["actual"]["paths"]["tls_c2s"].erase("limit_packets");
    std::ofstream(zero_provenance_path) << missing_limit.dump(2) << '\n';
    const auto missing_limit_report =
        client_report(pure_netem_dir / "zero", dir / "none-qdisc-missing-limit-report");
    assert(missing_limit_report["groups"][0]["automatic_comparison_eligible"] == false);
    assert(missing_limit_report["groups"][0]["metrics"].empty());

    auto netem_null_limit = zero_provenance;
    netem_null_limit["condition_identity"]["actual"]["paths"]["tls_c2s"]["limit_packets"] = nullptr;
    std::ofstream(zero_provenance_path) << netem_null_limit.dump(2) << '\n';
    const auto netem_null_limit_report =
        client_report(pure_netem_dir / "zero", dir / "netem-null-limit-report");
    assert(netem_null_limit_report["groups"][0]["automatic_comparison_eligible"] == false);
    assert(netem_null_limit_report["groups"][0]["metrics"].empty());
    std::ofstream(zero_provenance_path) << zero_provenance.dump(2) << '\n';

    auto host_changed_provenance = J::parse(std::ifstream(zero_provenance_path));
    host_changed_provenance["host_network_identity"]["unchanged"] = false;
    std::ofstream(zero_provenance_path) << host_changed_provenance.dump(2) << '\n';
    const auto host_changed_report =
        client_report(pure_netem_dir / "zero", dir / "host-changed-network-report");
    assert(host_changed_report["groups"].size() == 1);
    assert(host_changed_report["groups"][0]["dimensions"] == zero_dimensions);
    assert(host_changed_report["groups"][0]["automatic_comparison_eligible"] == false);
    assert(host_changed_report["groups"][0]["metrics"].empty());
    assert(host_changed_report["samples"][0]["network_integrity"]["eligible"] == false);

    const auto contexts_dir = dir / "context-identities";
    std::filesystem::create_directory(contexts_dir);
    for (const auto* folder : {"first", "second"}) {
        write_candidate(contexts_dir, folder, "same-adapter", "fixed-peer", "same-profile",
                        "same-library");
        for (const auto* role : {"client", "server"})
            update_header(contexts_dir / folder / (std::string(role) + ".jsonl"), [&](J& metadata) {
                metadata["loaded_context_size"] = 8;
                metadata["loaded_context_hash"] = "baseline-a";
            });
    }
    update_header(contexts_dir / "second/client.jsonl",
                  [](J& metadata) { metadata["loaded_context_hash"] = "baseline-b"; });
    assert(client_report(contexts_dir, dir / "context-report")["groups"].size() == 2);
    update_header(contexts_dir / "second/client.jsonl",
                  [](J& metadata) { metadata["loaded_context_hash"] = "baseline-a"; });
    update_header(contexts_dir / "second/server.jsonl",
                  [](J& metadata) { metadata["loaded_context_hash"] = "baseline-b"; });
    assert(client_report(contexts_dir, dir / "peer-context-report")["groups"].size() == 2);

    const auto unknown_context_dir = dir / "unknown-context";
    std::filesystem::create_directory(unknown_context_dir);
    for (const auto* adapter : {"adapter-a", "adapter-b"}) {
        write_candidate(unknown_context_dir, adapter, adapter, "fixed-peer", "same-profile",
                        adapter);
        update_header(unknown_context_dir / adapter / "client.jsonl",
                      [](J& metadata) { metadata["loaded_context_size"] = 8; });
    }
    const auto unknown_context = client_report(unknown_context_dir, dir / "unknown-context-report");
    assert(unknown_context["groups"].size() == 2);
    assert(unknown_context["comparisons"].empty());

    const auto missing_context_size_dir = dir / "missing-context-size";
    std::filesystem::create_directory(missing_context_size_dir);
    write_candidate(missing_context_size_dir, "observed-zero", "adapter-a", "fixed-peer",
                    "same-profile", "library-a");
    write_candidate(missing_context_size_dir, "missing", "adapter-b", "fixed-peer", "same-profile",
                    "library-b");
    for (const auto* role : {"client", "server"})
        update_header(missing_context_size_dir / "missing" / (std::string(role) + ".jsonl"),
                      [](J& metadata) {
                          metadata.erase("loaded_context_size");
                          metadata.erase("loaded_context_hash");
                      });
    const auto missing_context_size =
        client_report(missing_context_size_dir, dir / "missing-context-size-report");
    assert(missing_context_size["groups"].size() == 2);
    assert(missing_context_size["comparisons"].empty());

    const auto unknown_socket_dir = dir / "unknown-sockets";
    std::filesystem::create_directory(unknown_socket_dir);
    for (const auto* adapter : {"adapter-a", "adapter-b"}) {
        write_candidate(unknown_socket_dir, adapter, adapter, "fixed-peer", "same-profile",
                        adapter);
        for (const auto* role : {"client", "server"})
            update_header(unknown_socket_dir / adapter / (std::string(role) + ".jsonl"),
                          [](J& metadata) { metadata["connections"][0].erase("socket"); });
    }
    const auto unknown_socket = client_report(unknown_socket_dir, dir / "unknown-socket-report");
    assert(unknown_socket["groups"].size() == 2);
    assert(unknown_socket["comparisons"].empty());

    const auto runner_dir = dir / "runner-invalid";
    std::filesystem::create_directory(runner_dir);
    write_candidate(runner_dir, "sample", "adapter-a", "fixed-peer", "same-profile", "library-a");
    std::ofstream(runner_dir / "sample" / "client.failure.json")
        << J({{"run_id", (runner_dir / "sample").string()},
              {"context_id", "context"},
              {"reason", "endpoint failed during cleanup"}})
               .dump()
        << '\n';
    const auto runner_invalid = client_report(runner_dir, dir / "runner-report");
    assert(runner_invalid["groups"].empty());
    assert(runner_invalid["invalid_samples"] == 2);

    auto write_common_admission_sample = [&](const std::filesystem::path& root, bool header_valid,
                                             bool network_required) {
        std::filesystem::create_directories(root);
        auto metadata = header;
        metadata["valid"] = header_valid;
        metadata["connections"][0]["end_sequence"] = 6;
        metadata["config"]["tls"] = {{"application_bytes", 4}, {"framework_io", true}};
        metadata["config"]["channel_observer"] = false;
        if (network_required)
            metadata["config"]["network_handoff"] = {{"net_profile", {{"paths", J::object()}}}};
        std::ofstream raw(root / "client.jsonl");
        raw << metadata.dump() << '\n';
        for (const auto& event : common_events("client", false))
            raw << event.dump() << '\n';
    };
    auto common_available = [](const J& report) {
        return report["samples"][0]["connections"][0]
                     ["handshake_call_begin_to_application_complete"]["available"] == true;
    };
    auto common_metric_absent = [](const J& report) {
        for (const auto& group : report["groups"])
            if (group["metrics"].contains(
                    "handshake_call_begin_to_application_complete_elapsed_ns"))
                return false;
        return true;
    };

    const auto invalid_tls_dir = dir / "common-valid-boundary-invalid-tls";
    write_common_admission_sample(invalid_tls_dir, false, false);
    const auto invalid_tls = client_report(invalid_tls_dir, dir / "common-invalid-tls-report");
    assert(common_available(invalid_tls));
    assert(invalid_tls["groups"].empty() && common_metric_absent(invalid_tls));

    const auto invalid_network_dir = dir / "common-valid-boundary-invalid-network";
    write_common_admission_sample(invalid_network_dir, true, true);
    const auto invalid_network =
        client_report(invalid_network_dir, dir / "common-invalid-network-report");
    assert(common_available(invalid_network));
    assert(!invalid_network["groups"].empty() && common_metric_absent(invalid_network));

    const auto invalid_parent_dir = dir / "common-valid-boundary-invalid-parent";
    const auto invalid_parent_sample = invalid_parent_dir / "sample-1";
    write_common_admission_sample(invalid_parent_sample, true, false);
    {
        std::ofstream ledger(invalid_parent_dir / "attempts.jsonl");
        ledger << J({{"type", "turtle-attempt-ledger"},
                     {"schema", 1},
                     {"record_kind", "run_config"},
                     {"requested_count", 1}})
                      .dump()
               << '\n';
        ledger << J({{"type", "turtle-attempt-ledger"},
                     {"schema", 1},
                     {"record_kind", "attempt_started"},
                     {"attempt_id", 1},
                     {"started", true}})
                      .dump()
               << '\n';
        ledger << J({{"type", "turtle-attempt-ledger"},
                     {"schema", 1},
                     {"record_kind", "attempt_final"},
                     {"attempt_id", 1},
                     {"final_status", "timeout"},
                     {"network_observation_ids", J::array()}})
                      .dump()
               << '\n';
        ledger << J({{"type", "turtle-attempt-ledger"},
                     {"schema", 1},
                     {"record_kind", "run_summary"},
                     {"requested", 1},
                     {"started", 1},
                     {"success", 0},
                     {"timeout", 1},
                     {"error", 0},
                     {"incomplete", 0},
                     {"not_attempted", 0},
                     {"missing_artifacts", 0},
                     {"missing_artifact_rows", J::array()}})
                      .dump()
               << '\n';
    }
    const auto invalid_parent = client_report(invalid_parent_dir, dir / "common-invalid-parent-report");
    assert(common_available(invalid_parent));
    assert(invalid_parent["groups"].empty() && common_metric_absent(invalid_parent));

    auto reject_bad_ledger = [&](const char* name, const std::string& contents) {
        const auto bad = dir / name;
        std::filesystem::create_directory(bad);
        write_candidate(bad, "sample", "adapter-a", "fixed-peer", "same-profile", "library-a");
        std::ofstream(bad / "attempts.jsonl") << contents;
        bool rejected = false;
        try {
            (void)client_report(bad, dir / (std::string(name) + "-report"));
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        assert(rejected);
    };
    reject_bad_ledger("empty-attempt-ledger", "");
    reject_bad_ledger("malformed-attempt-ledger", "{broken\n");
    reject_bad_ledger("middle-malformed-attempt-ledger",
                      "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,\"record_kind\":"
                      "\"run_config\",\"requested_count\":1}\n{broken\n"
                      "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,\"record_kind\":"
                      "\"run_summary\",\"requested\":1,\"started\":0,\"success\":0,"
                      "\"timeout\":0,\"error\":0,\"incomplete\":0,\"not_attempted\":1,"
                      "\"missing_artifacts\":0,\"missing_artifact_rows\":[]}\n");

    const auto truncated_ledger_dir = dir / "truncated-final-attempt-ledger";
    std::filesystem::create_directory(truncated_ledger_dir);
    write_candidate(truncated_ledger_dir, "sample", "adapter-a", "fixed-peer", "same-profile",
                    "library-a");
    {
        std::ofstream ledger(truncated_ledger_dir / "attempts.jsonl");
        ledger << "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
                  "\"record_kind\":\"run_config\",\"requested_count\":1}\n";
        ledger << "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
                  "\"record_kind\":\"attempt_started\",\"attempt_id\":1}\n";
        ledger << "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
                  "\"record_kind\":\"attempt_final\",\"attempt_id\":";
    }
    const auto truncated_ledger = client_report(truncated_ledger_dir, dir / "truncated-final-report");
    assert(truncated_ledger["groups"].empty());
    assert(truncated_ledger["invalid_samples"] == 2);
    for (const auto& sample : truncated_ledger["samples"])
        assert(sample["invalid_reason"] == "parent attempt ledger status: incomplete");
    std::filesystem::remove_all(dir);
    std::cout << "report tests passed\n";
}
