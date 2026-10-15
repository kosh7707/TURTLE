#include "report/report.hpp"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <numeric>
#include <unistd.h>
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
    J header = {{"role", "client"}, {"connections", J::array({{{"index", 0}, {"warmup", false}}})}};
    std::vector<J> events;
    auto add = [&](const char* kind, int time, const char* call = "handshake", int result = 0) {
        events.push_back({{"kind", kind},
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
    events.front()["heap"] = {{"live", 10}, {"interval_peak", 1000}};
    events.back()["heap"] = {{"live", 10}, {"interval_peak", 20}};
    assert(partition(header, events)[0]["heap_peak_bytes"] == 20);
    auto kernel = events.front();
    kernel["location"] = "kernel";
    kernel["monotonic_ns"] = 999999;
    events.insert(events.begin() + 2, kernel);
    assert(partition(header, events)[0]["elapsed_ns"] == 30);
    header.update({{"schema", 1},
                   {"type", "sample"},
                   {"sample", 1},
                   {"batch", 1},
                   {"valid", true},
                   {"profile_hash", "test"},
                   {"environment_hash", "env"},
                   {"mode", "timing"},
                   {"config", J::object()},
                   {"declaration", {{"library", "fixture"}, {"is_mock", true}}}});
    const auto dir =
        std::filesystem::temp_directory_path() / ("turtle-report-" + std::to_string(getpid()));
    std::filesystem::create_directories(dir);
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

    const auto raw_only_dir = dir / "raw-only-fixture";
    std::filesystem::create_directory(raw_only_dir);
    std::filesystem::copy_file(fixture_root / "client.jsonl", raw_only_dir / "client.jsonl");
    const auto raw_only = summarize(raw_only_dir, dir / "raw-only-report");
    assert(raw_only["samples"][0]["decoded_sidecar_status"] == "absent");
    assert(raw_only["samples"][0]["decoded_sidecar_reason"] == "optional_sidecar_not_present");
    assert(!raw_only["samples"][0]["connections"][0].contains("client_hello_to_finished_send"));
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
    for (int i = 0; i < 4; ++i) {
        auto alternate = header;
        if (i == 0)
            alternate["config"]["server_adapter"] = "different_peer";
        if (i == 1)
            alternate["pinned_cpu"] = 3;
        if (i == 2)
            alternate["config"]["perf"] = true;
        if (i == 3)
            alternate["declaration"]["build_options"] = "different_build";
        auto folder = dir / std::to_string(i);
        std::filesystem::create_directory(folder);
        std::ofstream raw(folder / "client.jsonl");
        raw << alternate.dump() << '\n';
        for (const auto& e : events)
            raw << e.dump() << '\n';
    }
    const auto separated = summarize(dir, dir / "grouped");
    assert(separated["groups"].size() >= 5);

    const auto candidates_dir = dir / "comparison-candidates";
    std::filesystem::create_directory(candidates_dir);
    const J socket = {{"nonblocking", true}, {"tcp_nodelay", true},
                     {"send_buffer", 131072}, {"receive_buffer", 131072},
                     {"kernel_timestamps", false}};
    auto write_candidate = [&](const std::filesystem::path& root, const std::string& folder_name,
                               const std::string& own_adapter, const std::string& peer_adapter,
                               const std::string& profile, const std::string& library,
                               std::uint64_t batch = 1, int peer_cpu = 8,
                               const std::string& peer_version = "peer-version",
                               bool include_peer = true) {
        auto candidate = header;
        candidate["batch"] = batch;
        candidate["config"]["client_adapter"] = own_adapter;
        candidate["config"]["server_adapter"] = peer_adapter;
        candidate["profile_hash"] = profile;
        candidate["pinned_cpu"] = 6;
        candidate["capabilities"] = {{"perf", false}, {"affinity", true}};
        candidate["declaration"]["library"] = library;
        candidate["declaration"]["version"] = library + "-version";
        candidate["declaration"]["build_options"] = library + "-build";
        candidate["loaded_context_size"] = 0;
        candidate["loaded_context_hash"] = "";
        candidate["connections"][0]["socket"] = socket;
        const auto folder = root / folder_name;
        std::filesystem::create_directory(folder);
        std::ofstream raw(folder / "client.jsonl");
        raw << candidate.dump() << '\n';
        for (const auto& event : events) {
            raw << event.dump() << '\n';
        }
        raw.close();
        if (include_peer) {
            auto peer = candidate;
            peer["role"] = "server";
            peer["pinned_cpu"] = peer_cpu;
            peer["declaration"]["library"] = "peer-library";
            peer["declaration"]["version"] = peer_version;
            peer["declaration"]["build_options"] = "peer-build";
            std::ofstream(folder / "server.jsonl") << peer.dump() << '\n';
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
    const auto candidates = summarize(candidates_dir, dir / "candidate-report");
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
    assert(candidates["comparisons"].size() == 1);
    assert(candidates["comparisons"][0]["method"] == "independent_percentile_bootstrap");
    assert(candidates["comparisons"][0]["interpretation"] ==
           "exploratory_adapter_candidate_not_equivalence");
    assert(candidates["comparisons"][0]["eligibility"] ==
           "same_conditions_verified_fixed_peer_and_batch_ids_except_measured_adapter_identity");

    const auto disjoint_dir = dir / "disjoint-batches";
    std::filesystem::create_directory(disjoint_dir);
    write_candidate(disjoint_dir, "batch-one", "adapter-one", "fixed-peer", "same-profile",
                    "library-one", 1);
    write_candidate(disjoint_dir, "batch-two", "adapter-two", "fixed-peer", "same-profile",
                    "library-two", 2);
    const auto disjoint = summarize(disjoint_dir, dir / "disjoint-report");
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
    assert(summarize(sockets_dir, dir / "socket-report")["groups"].size() == 2);
    update_header(sockets_dir / "second/client.jsonl", [&](J& metadata) {
        metadata["connections"][0]["socket"] = socket;
    });
    update_header(sockets_dir / "second/server.jsonl", [](J& metadata) {
        metadata["connections"][0]["socket"]["receive_buffer"] = 262144;
    });
    assert(summarize(sockets_dir, dir / "peer-socket-report")["groups"].size() == 2);

    const auto warmup_sockets_dir = dir / "warmup-socket-settings";
    std::filesystem::create_directory(warmup_sockets_dir);
    for (const auto* folder : {"first", "second"}) {
        write_candidate(warmup_sockets_dir, folder, "same-adapter", "fixed-peer",
                        "same-profile", "same-library");
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
    const auto warmup_sockets =
        summarize(warmup_sockets_dir, dir / "warmup-socket-report");
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
    write_candidate(missing_warmup_socket_dir, "missing", "adapter-b", "fixed-peer",
                    "same-profile", "library-b");
    for (const auto* folder : {"complete", "missing"})
        for (const auto* role : {"client", "server"})
            update_header(missing_warmup_socket_dir / folder /
                              (std::string(role) + ".jsonl"),
                          [&](J& metadata) {
                              metadata["config"]["warmups"] = 1;
                              metadata["connections"].push_back(
                                  {{"index", 1}, {"warmup", true}, {"socket", socket}});
                          });
    update_header(missing_warmup_socket_dir / "missing/client.jsonl", [](J& metadata) {
        metadata["connections"][1].erase("socket");
    });
    const auto missing_warmup_socket =
        summarize(missing_warmup_socket_dir, dir / "missing-warmup-socket-report");
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
            update_header(run / "sample-1" / (std::string(role) + ".jsonl"),
                          [&](J& metadata) {
                              metadata["config"]["network_handoff"] = J::object();
                              metadata["config"]["network_handoff"]["net_profile"] = {
                                  {"paths", {{"tls_c2s", {{"delay_ms", delay_ms}}},
                                             {"tls_s2c", {{"delay_ms", delay_ms}}}}}};
                          });
        const J observation_ids = J::array(
            {"1:setup:begin", "1:setup:end", "1:scenario:begin", "1:scenario:end",
             "1:cleanup:begin", "1:cleanup:end"});
        {
            std::ofstream ledger(run / "attempts.jsonl");
            ledger << J({{"type", "turtle-attempt-ledger"}, {"schema", 1},
                         {"record_kind", "run_config"}, {"requested_count", 1}})
                              .dump()
                   << '\n';
            ledger << J({{"type", "turtle-attempt-ledger"}, {"schema", 1},
                         {"record_kind", "attempt_started"}, {"attempt_id", 1},
                         {"started", true}, {"final_status", "not_attempted"},
                         {"network_observation_ids", J::array()}})
                              .dump()
                   << '\n';
            ledger << J({{"type", "turtle-attempt-ledger"}, {"schema", 1},
                         {"record_kind", "attempt_final"}, {"attempt_id", 1},
                         {"final_status", "success"},
                         {"network_observation_ids", observation_ids}})
                              .dump()
                   << '\n';
            ledger << J({{"type", "turtle-attempt-ledger"}, {"schema", 1},
                         {"record_kind", "run_summary"}, {"requested", 1},
                         {"started", 1}, {"success", 1}, {"timeout", 0},
                         {"error", 0}, {"incomplete", 0}, {"not_attempted", 0},
                         {"missing_artifacts", 0}, {"missing_artifact_rows", J::array()}})
                              .dump()
                   << '\n';
        }
        const J paths = {
            {"tls_c2s", {{"delay_ms", delay_ms}, {"loss_percent", 0.0}, {"limit_packets", 10000}}},
            {"tls_s2c", {{"delay_ms", delay_ms}, {"loss_percent", 0.0}, {"limit_packets", 10000}}}};
        const J readbacks = {
            {"tls_c2s", {{"interface", "rstls"}}},
            {"tls_s2c", {{"interface", "rctls"}}}};
        std::ofstream(run / "network-provenance.json")
            << J({{"type", "turtle-network-provenance"}, {"schema", 1},
                  {"status", "complete"}, {"director", {{"returncode", 0}}},
                  {"host_network_identity", {{"unchanged", true},
                                               {"before", {{"supported", true}}},
                                               {"after", {{"supported", true}}}}},
                  {"lifecycle", {{"namespace_fds_closed", true},
                                   {"owned_pipe_fds_closed", true}}},
                  {"cleanup", J::array({{{"helper", "client"}, {"result", "reaped"}},
                                         {{"helper", "server"}, {"result", "reaped"}},
                                         {{"helper", "router"}, {"result", "reaped"}}})},
                  {"finished_monotonic_ns", 1000},
                  {"applied_qdisc_readback", readbacks},
                  {"condition_identity",
                   {{"topology", {{"kind", "three-netns-receiver-facing-router-egress"},
                                    {"addresses", {{"client_tls", "10.203.1.2"},
                                                    {"server", "10.203.2.2"}}},
                                    {"interfaces", {{"client_tls", "ctls"},
                                                     {"server", "stls"},
                                                     {"router_client_tls", "rctls"},
                                                     {"router_server", "rstls"}}}}},
                    {"requested", {{"paths", paths}}},
                    {"actual", {{"qdisc", "netem"}, {"paths", paths}}},
                    {"mtu", {{"requested", 1500}, {"actual", {{"ctls", 1500}}}}},
                    {"offload", {{"requested", false}, {"actual", {{"ctls", false}}}}},
                    {"trace", {{"requested", false}}}}}})
                   .dump(2)
            << '\n';
        std::ofstream observations(run / "network-observations.jsonl");
        for (const auto& id : observation_ids) {
            const auto text = id.get<std::string>();
            const auto phase = text.find(":setup:") != std::string::npos
                                   ? "setup"
                                   : text.find(":cleanup:") != std::string::npos ? "cleanup"
                                                                                  : "scenario";
            observations << J({{"type", "network-observation"}, {"schema", 1},
                               {"observation_id", text}, {"attempt", 1},
                               {"phase", phase},
                               {"edge", text.ends_with("begin") ? "begin" : "end"}})
                                    .dump()
                         << '\n';
        }
    };
    write_network_run("zero", 0);
    write_network_run("twenty", 20);
    const auto pure_netem = summarize(pure_netem_dir, dir / "pure-netem-report");
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
        if (dimensions["network_actual_identity"]["actual"]["paths"]["tls_c2s"]
                      ["delay_ms"] == 0)
            zero_dimensions = dimensions;
    }
    const auto zero_provenance_path = pure_netem_dir / "zero" / "network-provenance.json";
    auto host_changed_provenance = J::parse(std::ifstream(zero_provenance_path));
    host_changed_provenance["host_network_identity"]["unchanged"] = false;
    std::ofstream(zero_provenance_path) << host_changed_provenance.dump(2) << '\n';
    const auto host_changed_report =
        summarize(pure_netem_dir / "zero", dir / "host-changed-network-report");
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
            update_header(contexts_dir / folder / (std::string(role) + ".jsonl"),
                          [&](J& metadata) {
                              metadata["loaded_context_size"] = 8;
                              metadata["loaded_context_hash"] = "baseline-a";
                          });
    }
    update_header(contexts_dir / "second/client.jsonl", [](J& metadata) {
        metadata["loaded_context_hash"] = "baseline-b";
    });
    assert(summarize(contexts_dir, dir / "context-report")["groups"].size() == 2);
    update_header(contexts_dir / "second/client.jsonl", [](J& metadata) {
        metadata["loaded_context_hash"] = "baseline-a";
    });
    update_header(contexts_dir / "second/server.jsonl", [](J& metadata) {
        metadata["loaded_context_hash"] = "baseline-b";
    });
    assert(summarize(contexts_dir, dir / "peer-context-report")["groups"].size() == 2);

    const auto unknown_context_dir = dir / "unknown-context";
    std::filesystem::create_directory(unknown_context_dir);
    for (const auto* adapter : {"adapter-a", "adapter-b"}) {
        write_candidate(unknown_context_dir, adapter, adapter, "fixed-peer", "same-profile",
                        adapter);
        update_header(unknown_context_dir / adapter / "client.jsonl", [](J& metadata) {
            metadata["loaded_context_size"] = 8;
        });
    }
    const auto unknown_context = summarize(unknown_context_dir, dir / "unknown-context-report");
    assert(unknown_context["groups"].size() == 2);
    assert(unknown_context["comparisons"].empty());

    const auto missing_context_size_dir = dir / "missing-context-size";
    std::filesystem::create_directory(missing_context_size_dir);
    write_candidate(missing_context_size_dir, "observed-zero", "adapter-a", "fixed-peer",
                    "same-profile", "library-a");
    write_candidate(missing_context_size_dir, "missing", "adapter-b", "fixed-peer",
                    "same-profile", "library-b");
    for (const auto* role : {"client", "server"})
        update_header(missing_context_size_dir / "missing" /
                          (std::string(role) + ".jsonl"),
                      [](J& metadata) {
                          metadata.erase("loaded_context_size");
                          metadata.erase("loaded_context_hash");
                      });
    const auto missing_context_size =
        summarize(missing_context_size_dir, dir / "missing-context-size-report");
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
    const auto unknown_socket = summarize(unknown_socket_dir, dir / "unknown-socket-report");
    assert(unknown_socket["groups"].size() == 2);
    assert(unknown_socket["comparisons"].empty());

    const auto director_dir = dir / "director-invalid";
    std::filesystem::create_directory(director_dir);
    write_candidate(director_dir, "sample", "adapter-a", "fixed-peer", "same-profile", "library-a");
    std::ofstream(director_dir / "sample" / "director.txt") << "invalid: endpoint failed\n";
    const auto director_invalid = summarize(director_dir, dir / "director-report");
    assert(director_invalid["groups"].empty());
    assert(director_invalid["invalid_samples"] == 2);
    auto reject_bad_ledger = [&](const char* name, const std::string& contents) {
        const auto bad = dir / name;
        std::filesystem::create_directory(bad);
        write_candidate(bad, "sample", "adapter-a", "fixed-peer", "same-profile", "library-a");
        std::ofstream(bad / "attempts.jsonl") << contents;
        bool rejected = false;
        try {
            (void)summarize(bad, dir / (std::string(name) + "-report"));
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        assert(rejected);
    };
    reject_bad_ledger("empty-attempt-ledger", "");
    reject_bad_ledger("malformed-attempt-ledger", "{broken\n");
    reject_bad_ledger(
        "middle-malformed-attempt-ledger",
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,\"record_kind\":"
        "\"run_config\",\"requested_count\":1}\n{broken\n"
        "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,\"record_kind\":"
        "\"run_summary\",\"requested\":1,\"started\":0,\"success\":0,"
        "\"timeout\":0,\"error\":0,\"incomplete\":0,\"not_attempted\":1,"
        "\"missing_artifacts\":0,\"missing_artifact_rows\":[]}\n");

    const auto truncated_ledger_dir = dir / "truncated-final-attempt-ledger";
    std::filesystem::create_directory(truncated_ledger_dir);
    write_candidate(truncated_ledger_dir, "sample", "adapter-a", "fixed-peer",
                    "same-profile", "library-a");
    {
        std::ofstream ledger(truncated_ledger_dir / "attempts.jsonl");
        ledger << "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
                  "\"record_kind\":\"run_config\",\"requested_count\":1}\n";
        ledger << "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
                  "\"record_kind\":\"attempt_started\",\"attempt_id\":1}\n";
        ledger << "{\"type\":\"turtle-attempt-ledger\",\"schema\":1,"
                  "\"record_kind\":\"attempt_final\",\"attempt_id\":";
    }
    const auto truncated_ledger =
        summarize(truncated_ledger_dir, dir / "truncated-final-report");
    assert(truncated_ledger["groups"].empty());
    assert(truncated_ledger["invalid_samples"] == 2);
    for (const auto& sample : truncated_ledger["samples"])
        assert(sample["invalid_reason"] == "parent attempt ledger status: incomplete");
    std::filesystem::remove_all(dir);
    std::cout << "report tests passed\n";
}
