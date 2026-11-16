#include "journal.hpp"
#include "digest/digest.hpp"
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <unistd.h>
namespace turtle {
using json = nlohmann::json;
static json stamp(const Stamp& s, bool cpu, Availability counters, bool allocation) {
    json memory = nullptr;
    if (allocation)
        memory = {{"live_requested_bytes", s.allocation.live},
                  {"peak_requested_bytes", s.allocation.peak},
                  {"allocated_bytes", s.allocation.allocated},
                  {"freed_bytes", s.allocation.freed},
                  {"allocations", s.allocation.allocations},
                  {"frees", s.allocation.frees},
                  {"unowned_frees", s.allocation.unowned_frees}};
    return {
        {"allocation", memory},
        {"monotonic_ns", s.wall},
        {"thread_cpu_ns", cpu ? json(s.cpu) : json(nullptr)},
        {"cycles", counters == Availability::Available ? json(s.cycles) : json(nullptr)},
        {"instructions",
         counters == Availability::Available ? json(s.instructions) : json(nullptr)},
        {"time_enabled", counters == Availability::Available ? json(s.enabled) : json(nullptr)},
        {"time_running", counters == Availability::Available ? json(s.running) : json(nullptr)}};
}
void save_events(const Spec& s, const Observer& o, const turtle_support& support,
                 const std::string& failure) {
    std::ofstream file(s.output + "/events.jsonl");
    file.exceptions(std::ios::badbit | std::ios::failbit);
    std::uint64_t seq = 0;
    for (const auto& e : o.events) {
        json j = {
            {"contract", "turtle-message-events/1"},
            {"run_id", s.run_id},
            {"context_id", s.context_id},
            {"role", s.role == TURTLE_CLIENT ? "client" : "server"},
            {"sequence", ++seq},
            {"connection_id", e.connection},
            {"kind", kind_name(e.kind)},
            {"message_id", e.message},
            {"record_id", e.record},
            {"batch_id", e.batch},
            {"outgoing", e.outgoing},
            {"type", e.type},
            {"detail", e.detail},
            {"stream_offset", e.offset},
            {"bytes", e.length},
            {"plain_offset", e.plain_offset},
            {"plain_bytes", e.plain_length},
            {"begin", e.kind == Kind::Message || e.kind == Kind::Record
                          ? json(nullptr)
                          : stamp(e.begin, s.cpu,
                                  e.kind == Kind::FrameworkPreparation ? Availability::NotCollected
                                                                       : o.counters,
                                  e.kind != Kind::FrameworkPreparation && s.allocations)},
            {"end", e.kind == Kind::Message || e.kind == Kind::Record
                        ? json(nullptr)
                        : stamp(e.end, s.cpu,
                                e.kind == Kind::FrameworkPreparation ? Availability::NotCollected
                                                                     : o.counters,
                                e.kind != Kind::FrameworkPreparation && s.allocations)}};
        file << j.dump() << '\n';
    }
    json credentials = json::object();
    for (const char* name : {"ca.pem", "server-chain.pem", "client-chain.pem"}) {
        std::ifstream f(s.pki + "/" + name, std::ios::binary);
        if (!f) {
            credentials[name] = {{"status", "missing"}, {"bytes", nullptr}, {"sha256", nullptr}};
            continue;
        }
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(f)), {});
        if (f.bad())
            throw std::runtime_error("credential provenance read failed");
        credentials[name] =
            {{"status", "available"}, {"bytes", bytes.size()}, {"sha256", sha256(bytes)}};
    }
    json manifest = {
        {"contract", "turtle-message-manifest/1"},
        {"run_id", s.run_id},
        {"context_id", s.context_id},
        {"pid", getpid()},
        {"role", s.role == TURTLE_CLIENT ? "client" : "server"},
        {"implementation", support.name},
        {"source", support.source},
        {"credentials", credentials},
        {"credential_preparation", s.mutual                  ? "trust-and-local-identity"
                                   : s.role == TURTLE_CLIENT ? "trust-only"
                                                             : "local-identity-only"},
        {"technique", support.technique},
        {"scenario", scenario_name(s.scenario)},
        {"mutual_auth", s.mutual},
        {"group", s.group},
        {"network_condition", s.network_condition},
        {"depth", s.white ? "white-box" : "black-box"},
        {"records", s.bundle ? "bundle" : "preserve"},
        {"send", s.hello_first ? "server-hello-first" : "flight"},
        {"record_size", s.record_size},
        {"connections", s.connections},
        {"warmups", s.warmups},
        {"seed", s.seed},
        {"client_bytes", s.client_bytes},
        {"server_bytes", s.server_bytes},
        {"success", failure.empty()},
        {"failure", failure.empty() ? json(nullptr) : json(failure)},
        {"clock_domain", s.context_id},
        {"observation",
         {{"time", "CLOCK_MONOTONIC"},
          {"cpu", s.cpu ? "CLOCK_THREAD_CPUTIME_ID" : "not-collected"},
          {"perf", availability_name(o.counters)},
          {"perf_scope", "user-thread"},
          {"allocation", !s.allocations          ? "not-collected"
                         : o.allocations.missing ? "missing"
                                                 : "available"},
          {"allocation_location", "link-wrapped malloc/calloc/realloc/free during implementation "
                                  "calls; requested bytes; dynamic libc internals excluded"},
          {"stream", s.stream ? "socket-submission-and-receive" : "not-collected"},
          {"kernel", s.kernel ? "external-collection-requested" : "not-collected"},
          {"cpu_samples", s.cpu_samples ? "separate-collection-requested" : "not-collected"}}},
        {"lookup",
         {{"enabled", !s.lookup_digest.empty()},
          {"source", s.lookup_snapshot.empty() ? "independent-service" : "fixed-snapshot"},
          {"sha256", s.lookup_digest},
          {"bytes", s.lookup_size}}},
        {"buffers",
         {{"framework_max_message", s.max_message},
          {"framework_event_capacity", s.event_capacity},
          {"framework_event_reserved_bytes", s.event_capacity * sizeof(Event)},
          {"framework_allocation_registry_bytes", o.allocations.storage_bytes()},
          {"framework_protocol_buffer_bytes", 4 * s.max_message + 3 * 18432 + 65536 + 16384},
          {"framework_stream_reserved_bytes", s.stream ? 8 * (2 * s.max_message + 65536) : 0},
          {"implementation", "per-connection result.json storage inventory"}}},
        {"completion",
         "local required sends submitted to socket and received messages processed and verified"}};
    std::ofstream out(s.output + "/manifest.json");
    out.exceptions(std::ios::failbit | std::ios::badbit);
    out << manifest.dump(2) << '\n';
}
void save_stream(const std::string& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream f(path, std::ios::binary);
    f.exceptions(std::ios::badbit | std::ios::failbit);
    f.write(reinterpret_cast<const char*>(bytes.data()), std::streamsize(bytes.size()));
}
} // namespace turtle
