#include "model/sample.hpp"
#include "record/record.hpp"
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <new>
#include <nlohmann/json.hpp>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
bool forbid_allocation = false;
}
void* operator new(std::size_t size) {
    if (forbid_allocation)
        std::abort();
    if (void* p = std::malloc(size ? size : 1))
        return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept {
    std::free(p);
}
void operator delete(void* p, std::size_t) noexcept {
    std::free(p);
}

int main() {
    using namespace turtle;
    record::Buffer buffer({2, 4, 4, 2});
    model::Event e;
    e.sequence = 42;
    forbid_allocation = true;
    auto* prepared = buffer.prepare_event(e);
    assert(prepared != nullptr);
    prepared->snapshot.monotonic_ns = 99;
    assert(buffer.events().size() == 1);
    assert(buffer.events()[0].sequence == 42);
    assert(buffer.events()[0].snapshot.monotonic_ns == 99);
    const std::uint8_t data[]{1, 2, 3, 4};
    assert(buffer.append_bytes(0, model::Direction::Sent, data));
    assert(buffer.append_bytes(1, model::Direction::Received, data));
    assert(buffer.bytes(0, model::Direction::Received).empty());
    assert(buffer.bytes(1, model::Direction::Received).size() == 4);
    assert(!buffer.append_bytes(0, model::Direction::Sent, {data, 1}));
    assert(buffer.bytes(0, model::Direction::Sent).size() == 4);
    assert(buffer.append_keylog("abc"));
    assert(buffer.keylog() == "abc\n");
    assert(!buffer.append_keylog("d"));
    assert(buffer.append_plaintext(0, true, 22, data));
    assert(!buffer.append_plaintext(0, true, 22, {data, 1}));
    assert(buffer.plaintext_messages().size() == 1);
    assert(buffer.overflowed() && buffer.dropped() == 3);
    assert(buffer.append(e));
    assert(!buffer.append(e));
    forbid_allocation = false;
    const auto dir =
        std::filesystem::temp_directory_path() / ("turtle-record-" + std::to_string(getpid()));
    std::filesystem::create_directory(dir);
    {
        record::Writer writer(dir.string(), Role::Client, 2);
        model::SampleInfo info;
        info.sample = 7;
        info.declaration.read_ahead = false;
        info.declaration.read_ahead_note = "exact-needed receive policy";
        info.config.flush_grace_ms = 700;
        info.config.cpu = 11;
        info.config.channel_observer = false;
        info.config.perf_scope = model::PerfScope::UserKernel;
        info.capabilities.perf = true;
        info.capabilities.perf_requested_scope = model::PerfScope::UserKernel;
        info.capabilities.perf_status = model::PerfStatus::Available;
        info.capabilities.perf_effective_scope = model::PerfScope::UserKernel;
        info.environment.perf_event_paranoid = 2;
        model::CpuTopology topology;
        topology.cpu = 4;
        topology.package_id = 0;
        topology.core_id = 2;
        topology.thread_siblings = std::vector<model::CpuSibling>{{4, true}, {5, std::nullopt}};
        info.environment.cpu_topology.push_back(std::move(topology));
        info.config.lookup.enabled = true;
        info.config.lookup.cache_mode = model::CacheMode::FixedSnapshot;
        info.config.lookup.object_file = "/input/server-chain.pem";
        info.config.lookup.snapshot_file = "/input/cache.json";
        model::NetworkHandoff handoff;
        handoff.provenance_file = "/run/network-provenance.json";
        handoff.observations_file = "/run/network-observations.jsonl";
        handoff.net_profile_document =
            R"({"type":"turtle-netem-profile","schema":1,"qdisc":"none"})";
        info.config.network_handoff = handoff;
        info.connections.emplace_back();
        info.connections.back().primary_window_available = false;
        info.connections.back().primary_window_reason = "server_first_receive_not_observed";
        info.tls_stream_available = false;
        info.tls_stream_reason = "native_socket_io_not_observed";
        info.io_events_available = false;
        info.io_events_reason = "native_socket_io_not_observed";
        info.kernel_receive_events_available = false;
        info.kernel_receive_events_reason = "native_socket_io_not_observed";
        model::TcpInfoSnapshot tcp_start;
        tcp_start.structure_bytes = 104;
        tcp_start.total_retrans = 0;
        tcp_start.note = "short structure: optional fields unavailable";
        info.connections.back().tcp_start = tcp_start;
        const auto child = fork();
        assert(child >= 0);
        if (child == 0) {
            const rlimit limit{0, 0};
            // Sanitizer runtimes may open /proc/self/maps during checks. The
            // ordinary test always covers the resource-limit boundary.
            if (!std::getenv("TURTLE_TEST_SKIP_LIMITS") && setrlimit(RLIMIT_NOFILE, &limit) != 0)
                _exit(2);
            writer.write(info, buffer);
            writer.write_context(data);
            _exit(0);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    std::ifstream input(dir / "client.jsonl");
    nlohmann::json sample, event;
    input >> sample >> event;
    assert(sample["sample"] == 7 && sample["valid"] == false);
    assert(sample["schema"] == model::record_schema);
    assert(sample["measurement_contract_revision"] == model::measurement_contract_revision);
    assert(sample["measurement_contract_revision"] == 4);
    assert(sample["declaration"]["read_ahead"] == false);
    assert(sample["declaration"]["read_ahead_note"] == "exact-needed receive policy");
    assert(sample["capture_dropped"] == 4);
    assert(sample["connections"][0].contains("socket"));
    assert(sample["connections"][0]["socket"].is_null());
    assert(sample["connections"][0]["tcp_start"]["total_retrans"] == 0);
    assert(sample["connections"][0]["tcp_start"]["state"].is_null());
    assert(sample["connections"][0]["tcp_end"].is_null());
    assert(sample["connections"][0]["start_sequence"].is_null());
    assert(sample["connections"][0]["primary_window"]["available"] == false);
    assert(sample["connections"][0]["primary_window"]["reason"] ==
           "server_first_receive_not_observed");
    for (const auto* field : {"tls_stream", "io_events", "kernel_receive_events"}) {
        assert(sample["availability"][field]["available"] == false);
        assert(sample["availability"][field]["reason"] == "native_socket_io_not_observed");
    }
    const auto& config = sample["config"];
    assert(config["scenario_name"] == model::lookup_scenario_name);
    assert(!config.contains("failure_policy") && !config.contains("samples"));
    assert(config["flush_grace_ms"] == 700);
    assert(config["cpu"] == 11);
    assert(config["channel_observer"] == false);
    assert(config["perf_scope"] == "user+kernel");
    assert(sample["capabilities"]["perf_requested_scope"] == "user+kernel");
    assert(sample["capabilities"]["perf_status"] == "available");
    assert(sample["capabilities"]["perf_effective_scope"] == "user+kernel");
    assert(sample["capabilities"]["perf_failure_stage"].is_null());
    assert(sample["capabilities"]["perf_error_number"].is_null());
    assert(sample["environment"]["perf_event_paranoid"] == 2);
    assert(sample["environment"]["cpu_topology"][0]["thread_siblings"][1]["online"].is_null());
    assert(config["lookup"]["enabled"] == true);
    assert(config["lookup"]["cache_mode"] == "fixed-snapshot");
    assert(config["lookup"]["object_file"] == "/input/server-chain.pem");
    assert(config["lookup"]["snapshot_file"] == "/input/cache.json");
    assert(!config.contains("network_manifest"));
    assert(config["network_handoff"]["provenance_file"] == "/run/network-provenance.json");
    assert(config["network_handoff"]["observations_file"] == "/run/network-observations.jsonl");
    assert(config["network_handoff"]["net_profile"]["qdisc"] == "none");
    assert(!config["network_handoff"].contains("client_namespace_fd"));
    assert(!config["network_handoff"].contains("phase_control_fd"));
    assert(event["cycles"].is_null() && event["heap"].is_null());
    assert(event["sequence"] == 42);
    assert(std::filesystem::file_size(dir / "client.conn-0.sent.bin") == 4);
    assert(std::filesystem::file_size(dir / "client.context.bin") == 4);

    const auto ordinary_dir = dir / "ordinary";
    std::filesystem::create_directory(ordinary_dir);
    {
        record::Writer ordinary_writer(ordinary_dir.string(), Role::Server, 0);
        model::SampleInfo ordinary;
        ordinary.role = Role::Server;
        record::Buffer ordinary_buffer({0, 0, 0, 0});
        ordinary_writer.write(ordinary, ordinary_buffer);
    }
    std::ifstream ordinary_input(ordinary_dir / "server.jsonl");
    nlohmann::json ordinary_sample;
    ordinary_input >> ordinary_sample;
    assert(ordinary_sample["config"]["scenario_name"] == "standard-tls");
    assert(ordinary_sample["config"]["channel_observer"] == true);
    assert(ordinary_sample["config"]["perf_scope"] == "user");
    assert(ordinary_sample["capabilities"]["perf_status"] == "disabled");
    assert(ordinary_sample["capabilities"]["perf_effective_scope"].is_null());
    assert(ordinary_sample["environment"]["perf_event_paranoid"].is_null());
    assert(ordinary_sample["config"]["lookup"]["enabled"] == false);
    assert(ordinary_sample["config"]["lookup"]["object_file"].is_null());
    assert(ordinary_sample["config"]["lookup"]["snapshot_file"].is_null());
    assert(ordinary_sample["config"]["network_manifest"].is_null());
    assert(ordinary_sample["config"]["network_handoff"].is_null());
    assert(ordinary_sample["declaration"]["read_ahead"].is_null());
    assert(ordinary_sample["declaration"]["read_ahead_note"] == "");
    std::filesystem::remove_all(dir);
    record::Buffer zero({0, 0, 0, 0});
    assert(!zero.append(e));
    assert(!zero.append_keylog(""));
    assert(!zero.append_bytes(0, model::Direction::Sent, {}));
    std::cout << "record tests passed\n";
}
