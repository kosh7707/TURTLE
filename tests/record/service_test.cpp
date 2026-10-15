#include "record/record.hpp"

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
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
    if (void* value = std::malloc(size ? size : 1))
        return value;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept {
    std::free(value);
}
void operator delete(void* value, std::size_t) noexcept {
    std::free(value);
}

int main() {
    using namespace turtle;
    const auto directory = std::filesystem::temp_directory_path() /
                           ("turtle-service-record-" + std::to_string(getpid()));
    std::filesystem::create_directory(directory);

    record::ServiceBuffer buffer({1, 4, 1});
    record::ServiceEvent event;
    event.kind = model::ServiceEventKind::RequestBegin;
    event.sample = 4;
    event.request_id = 1;
    event.sequence = 9;
    event.stream_id = "lookup-0";
    event.snapshot.monotonic_ns = 100;
    event.requested = 4;
    const std::uint8_t sent[]{1, 2, 3, 4};
    forbid_allocation = true;
    assert(buffer.append(event));
    assert(buffer.append_bytes(0, model::Direction::Sent, sent));
    assert(!buffer.append_bytes(0, model::Direction::Sent, {sent, 1}));
    assert(!buffer.append(event));
    forbid_allocation = false;
    assert(buffer.reserved_bytes() >= sizeof(record::ServiceEvent) + 8);

    record::ServiceMetadata metadata;
    metadata.sample = 4;
    metadata.cache_state_id = "empty";
    metadata.object_id = 7;
    metadata.object_size = 4;
    metadata.cache_capacity = 16;
    metadata.reference_bytes = 4;
    metadata.reference_capacity = 8;
    metadata.framework_reserved_bytes = buffer.reserved_bytes();
    metadata.pid = getpid();
    metadata.pinned_cpu = 2;
    metadata.capabilities.perf_requested_scope = model::PerfScope::UserKernel;
    metadata.capabilities.perf_status = model::PerfStatus::Unsupported;
    metadata.capabilities.perf_failure_stage = model::PerfFailureStage::CyclesOpen;
    metadata.capabilities.perf_error_number = 13;
    record::ServiceWriter writer(directory.string(), record::ServiceArtifact::CertificateLookup,
                                 1, metadata);
    record::ServiceConnectionInfo connection;
    connection.sample = 4;
    connection.request_id = 1;
    connection.stream_id = "lookup-0";
    connection.object_id = 7;
    connection.object_size = 4;
    connection.request_count = 1;
    connection.memory.domain = model::HeapDomain::Lookup;
    connection.memory.logical_cache_bytes = 4;
    connection.memory.cache_capacity = 16;
    connection.artifact_status = model::ArtifactStatus::Complete;

    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        const rlimit limit{0, 0};
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
            _exit(2);
        writer.write({&connection, 1}, buffer, model::ArtifactStatus::Complete, {});
        _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    std::ifstream input(directory / "lookup.jsonl");
    nlohmann::json header, row, summary, footer;
    input >> header >> row >> summary >> footer;
    assert(header["type"] == "certificate-lookup" && header["schema"] == 1);
    assert(header["record_kind"] == "header");
    assert(header["scenario_name"] == model::lookup_scenario_name);
    assert(header["object_id"] == "fnv1a64:0000000000000007");
    assert(header["initial_cache_bytes"] == 0);
    assert(header["cache_capacity"] == 16 && header["reference_capacity"] == 8);
    assert(header["framework_reserved_bytes"] == buffer.reserved_bytes());
    assert(header["capabilities"]["perf_requested_scope"] == "user+kernel");
    assert(header["capabilities"]["perf_status"] == "unsupported");
    assert(header["capabilities"]["perf_effective_scope"].is_null());
    assert(header["capabilities"]["perf_failure_stage"] == "cycles_open");
    assert(header["capabilities"]["perf_error_number"] == 13);
    assert(!header.contains("declaration") && !header.contains("verification"));
    assert(row["record_kind"] == "event" && row["stream_id"] == "lookup-0");
    assert(row["monotonic_ns"] == 100 && row["heap"].is_null());
    assert(summary["record_kind"] == "connection_summary");
    assert(summary["object_id"] == "fnv1a64:0000000000000007");
    assert(summary["logical_cache_bytes"] == 4);
    assert(footer["artifact_status"] == "partial" && footer["capture_dropped"] == 2);
    assert(std::filesystem::file_size(directory / "lookup-0.sent.bin") == 4);
    assert(std::filesystem::file_size(directory / "lookup-0.received.bin") == 0);

    record::ServiceBuffer empty({0, 0, 0});
    auto warm_metadata = metadata;
    warm_metadata.initial_cache_bytes = warm_metadata.object_size;
    record::ServiceWriter missing(directory.string(), record::ServiceArtifact::MockCa, 0,
                                  warm_metadata);
    missing.write({}, empty, model::ArtifactStatus::Missing, "child artifact absent");
    std::ifstream missing_input(directory / "ca.jsonl");
    nlohmann::json missing_header, missing_footer;
    missing_input >> missing_header >> missing_footer;
    assert(missing_header["initial_cache_bytes"] == 4);
    assert(missing_footer["artifact_status"] == "missing");
    assert(missing_footer["incomplete_reason"] == "child artifact absent");

    const auto bad_directory = directory / "bad";
    std::filesystem::create_directory(bad_directory);
    metadata.scenario_name = std::string("\xff", 1);
    record::ServiceWriter bad(bad_directory.string(), record::ServiceArtifact::MockCa, 0,
                              metadata);
    bool threw = false;
    try {
        bad.write({}, empty, model::ArtifactStatus::Complete, {});
    } catch (const nlohmann::json::type_error&) {
        threw = true;
    }
    assert(threw);
    std::ifstream bad_input(bad_directory / "ca.jsonl");
    std::string bad_text((std::istreambuf_iterator<char>(bad_input)), {});
    assert(bad_text.find("\"record_kind\":\"footer\"") == std::string::npos);

    std::filesystem::remove_all(directory);
}
