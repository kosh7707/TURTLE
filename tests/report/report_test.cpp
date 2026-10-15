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

    auto add_warmup = [&](const std::filesystem::path& path) {
        std::ifstream input(path);
        std::vector<J> lines;
        std::string line;
        while (std::getline(input, line))
            lines.push_back(J::parse(line));
        input.close();
        lines[0]["config"]["warmups"] = 1;
        lines[0]["config"]["connections"] = 1;
        lines[0]["connections"] =
            J::array({{{"index", 0}, {"warmup", true}, {"socket", socket}},
                      {{"index", 1}, {"warmup", false}, {"socket", socket}}});
        for (std::size_t i = 1; i < lines.size(); ++i)
            lines[i]["connection"] = 1;
        std::ofstream output(path);
        for (const auto& value : lines)
            output << value.dump() << '\n';
    };
    const auto warmup_sockets_dir = dir / "warmup-socket-settings";
    std::filesystem::create_directory(warmup_sockets_dir);
    for (const auto* folder : {"first", "second"}) {
        write_candidate(warmup_sockets_dir, folder, "same-adapter", "fixed-peer",
                        "same-profile", "same-library");
        for (const auto* role : {"client", "server"})
            add_warmup(warmup_sockets_dir / folder / (std::string(role) + ".jsonl"));
    }
    update_header(warmup_sockets_dir / "second/client.jsonl", [](J& metadata) {
        metadata["connections"][0]["socket"]["send_buffer"] = 262144;
    });
    const auto different_warmup =
        summarize(warmup_sockets_dir, dir / "warmup-socket-report");
    assert(different_warmup["groups"].size() == 2);
    assert(different_warmup["comparisons"].empty());

    const auto missing_warmup_dir = dir / "missing-warmup-socket";
    std::filesystem::create_directory(missing_warmup_dir);
    for (const auto* adapter : {"adapter-a", "adapter-b"}) {
        write_candidate(missing_warmup_dir, adapter, adapter, "fixed-peer", "same-profile",
                        adapter);
        for (const auto* role : {"client", "server"})
            add_warmup(missing_warmup_dir / adapter / (std::string(role) + ".jsonl"));
    }
    update_header(missing_warmup_dir / "adapter-b/client.jsonl", [](J& metadata) {
        metadata["connections"][0].erase("socket");
    });
    const auto missing_warmup =
        summarize(missing_warmup_dir, dir / "missing-warmup-socket-report");
    assert(missing_warmup["groups"].size() == 2);
    assert(missing_warmup["comparisons"].empty());
    bool preserved_missing_warmup = false;
    for (const auto& group : missing_warmup["groups"])
        preserved_missing_warmup =
            preserved_missing_warmup || group["dimensions"]["socket_settings"][0].is_null();
    assert(preserved_missing_warmup);

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
    std::filesystem::remove_all(dir);
    std::cout << "report tests passed\n";
}
