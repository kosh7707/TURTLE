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
    assert(buffer.append(e));
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
        info.config.flush_grace_ms = 700;
        info.config.failure_policy = model::FailurePolicy::FixedAttempts;
        info.config.ca_cpu = 11;
        info.config.lookup.enabled = true;
        info.config.lookup.cache_mode = model::CacheMode::FixedSnapshot;
        info.config.lookup.object_file = "/input/server-chain.pem";
        info.config.lookup.snapshot_file = "/input/cache.json";
        info.config.network_manifest = "/run/network-manifest.json";
        model::NetworkHandoff handoff;
        handoff.client_namespace_fd = 91;
        handoff.phase_control_fd = 92;
        handoff.provenance_file = "/run/network-provenance.json";
        handoff.observations_file = "/run/network-observations.jsonl";
        handoff.net_profile_document =
            R"({"type":"turtle-netem-profile","schema":1,"qdisc":"none"})";
        info.config.network_handoff = handoff;
        info.connections.emplace_back();
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
    assert(sample["capture_dropped"] == 4);
    assert(sample["connections"][0].contains("socket"));
    assert(sample["connections"][0]["socket"].is_null());
    assert(sample["connections"][0]["tcp_start"]["total_retrans"] == 0);
    assert(sample["connections"][0]["tcp_start"]["state"].is_null());
    assert(sample["connections"][0]["tcp_end"].is_null());
    const auto& config = sample["config"];
    assert(config["scenario_name"] == model::lookup_scenario_name);
    assert(config["failure_policy"] == "fixed-attempts" && config["flush_grace_ms"] == 700);
    assert(config["ca_cpu"] == 11);
    assert(config["lookup"]["enabled"] == true);
    assert(config["lookup"]["cache_mode"] == "fixed-snapshot");
    assert(config["lookup"]["object_file"] == "/input/server-chain.pem");
    assert(config["lookup"]["snapshot_file"] == "/input/cache.json");
    assert(config["network_manifest"] == "/run/network-manifest.json");
    assert(config["network_handoff"]["provenance_file"] ==
           "/run/network-provenance.json");
    assert(config["network_handoff"]["observations_file"] ==
           "/run/network-observations.jsonl");
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
    assert(ordinary_sample["config"]["lookup"]["enabled"] == false);
    assert(ordinary_sample["config"]["lookup"]["object_file"].is_null());
    assert(ordinary_sample["config"]["lookup"]["snapshot_file"].is_null());
    assert(ordinary_sample["config"]["network_manifest"].is_null());
    assert(ordinary_sample["config"]["network_handoff"].is_null());
    std::filesystem::remove_all(dir);
    record::Buffer zero({0, 0, 0, 0});
    assert(!zero.append(e));
    assert(!zero.append_keylog(""));
    assert(!zero.append_bytes(0, model::Direction::Sent, {}));
    std::cout << "record tests passed\n";
}
