#include "artifact/endpoint.hpp"
#include "artifact/json.hpp"
#include <fstream>
#include <sys/syscall.h>
#include <unistd.h>
namespace turtle::artifact {
namespace {
using namespace measure;
Json number(std::uint64_t n, bool available) {
  return available ? Json(n) : Json(nullptr);
}
Json stamp(const Stamp &s) {
  return {{"wall_ns", number(s.wall_ns, s.wall_available)},
          {"thread_cpu_ns", number(s.cpu_ns, s.cpu_available)}};
}
Json counter_stamp(const Stamp &s) {
  auto j = stamp(s);
  const auto &p = s.perf;
  j.update({{"available", p.available},
            {"tid", number(p.tid, p.tid > 0)},
            {"cycles", number(p.cycles, p.available)},
            {"instructions", number(p.instructions, p.available)},
            {"time_enabled_ns", number(p.enabled_ns, p.available)},
            {"time_running_ns", number(p.running_ns, p.available)},
            {"read_begin_ns", number(p.read_begin_ns, p.read_begin_ns != 0)},
            {"read_end_ns", number(p.read_end_ns, p.read_end_ns != 0)}});
  return j;
}
Json duration(const Stamp &a, const Stamp &b) {
  return {{"wall_ns",
           number(b.wall_ns - a.wall_ns, a.wall_available && b.wall_available &&
                                             b.wall_ns >= a.wall_ns)},
          {"thread_cpu_ns",
           number(b.cpu_ns - a.cpu_ns,
                  a.cpu_available && b.cpu_available && b.cpu_ns >= a.cpu_ns)}};
}
const char *name(Kind k) {
  switch (k) {
  case Kind::call:
    return "call";
  case Kind::transport:
    return "transport";
  case Kind::socket:
    return "socket";
  case Kind::header: return "header";
  case Kind::message: return "message";
  }
  return "unknown";
}
const char *name(Operation op) {
  switch (op) {
  case Operation::prepare:
    return "prepare";
  case Operation::handshake:
    return "handshake";
  case Operation::read:
    return "application_read";
  case Operation::write:
    return "application_write";
  case Operation::server_first: return "server_first";
  case Operation::verify: return "content_verify";
  case Operation::shutdown:
    return "shutdown";
  case Operation::none:
    return "none";
  }
  return "unknown";
}
Json optional(const std::string &s, bool collected) {
  return {{"availability", !collected  ? "not_collected"
                           : s.empty() ? "unsupported"
                                       : "available"},
          {"value", s.empty() ? Json(nullptr) : Json(s)}};
}
} // namespace
void write(const std::string &directory, const measure::Recorder &recorder,
           const Result &r) {
  const std::filesystem::path root(directory);
  Json identity = {{"run_id", r.run_id},
                   {"role", r.role},
                   {"pid", ::getpid()},
                   {"tid", syscall(SYS_gettid)}};
  const auto &c = recorder.counters();
  Json counters = identity;
  counters.update(
      {{"schema", r.role_sdk ? "turtle.counters.v2" : "turtle.counters.v1"},
       {"owner_tid", number(c.owner_tid(), c.owner_tid() > 0)},
       {"collector", "linux_perf_event_open_group"},
       {"requested", c.requested()},
       {"availability", measure::name(c.availability())},
       {"reason", c.reason() ? Json(c.reason()) : Json(nullptr)},
       {"errno", c.error_number()},
       {"scope", "calling_thread_user_space"},
       {"inherit", false},
       {"exclude_kernel", true},
       {"exclude_hv", true},
       {"clock", "CLOCK_MONOTONIC"},
       {"scaled", false},
       {"scenario",
        {{"begin", counter_stamp(r.begin)}, {"end", counter_stamp(r.end)}}},
       {"events", Json::array()}});
  std::ofstream events;
  if (recorder.calls()) events.open(root / "events.jsonl");
  for (const auto &e : recorder.events()) {
    counters["events"].push_back({{"id", e.id},
                                  {"begin", counter_stamp(e.begin)},
                                  {"end", counter_stamp(e.end)}});
    Json j = {
        {"schema", "turtle.event.v2"},
        {"run_id", r.run_id},
        {"connection_id", r.connection_id},
        {"role", r.role},
        {"id", e.id},
        {"parent", e.parent},
        {"call_id", e.call_id},
        {"kind", name(e.kind)},
        {"operation", name(e.operation)},
        {"direction", e.direction == Direction::send ? "send" : "receive"},
        {"requested", e.requested},
        {"transferred", e.transferred},
        {"tls_begin", e.tls_begin},
        {"tls_end", e.tls_end},
        {"wire_begin", e.wire_begin},
        {"wire_end", e.wire_end},
        {"success", e.success},
        {"begin", stamp(e.begin)},
        {"end", stamp(e.end)},
        {"duration", duration(e.begin, e.end)}};
    j["plaintext_begin"] = e.plaintext_begin;
    j["plaintext_end"] = e.plaintext_end;
    if (e.kind == Kind::socket) j["errno"] = e.error_number;
    if (e.source) j["source"] = e.source;
    if (e.kind == Kind::header) j["header"] = e.header;
    if (e.kind == Kind::message) j["message_type"] = e.message_type;
    events << j.dump() << '\n';
  }
  if (recorder.calls()) {
    events.close();
    if (!events) throw std::runtime_error("events_write_failed");
  }
  if (r.role == r.measured_role) save(root / "counters.json", counters);
  Json out = identity;
  out.update(
      {{"schema", "turtle.endpoint.v4"},
       {"connection_id", r.connection_id},
       {"implementation", r.implementation},
       {"purpose", r.purpose}, {"measured_role", r.measured_role},
       {"recording", r.recording}, {"auth", r.auth},
       {"application", {{"request_bytes", r.request_bytes}, {"greeting_bytes", r.greeting_bytes}, {"response_bytes", r.response_bytes}}},
       {"capability", {{"client_paused", r.client_paused}, {"server_presend", r.server_presend}, {"server_submitted", r.server_submitted}, {"queued_before_resume", r.queued_before_resume}}},
       {"status", r.scenario_complete
                      ? "ok"
                      : "invalid"},
       {"invalid_reason",
        r.invalid_reason.empty() ? Json(nullptr) : Json(r.invalid_reason)},
       {"observation_reason", r.observation_reason.empty()
                                  ? Json(nullptr)
                                  : Json(r.observation_reason)},
       {"shutdown", r.shutdown},
       {"shutdown_reason", r.shutdown_reason.empty() ? Json(nullptr) : Json(r.shutdown_reason)},
       {"observations_complete", recorder.complete()},
       {"clock",
        {{"wall", "CLOCK_MONOTONIC"}, {"cpu", "CLOCK_THREAD_CPUTIME_ID"}}},
       {"collection",
        {{"framing", "none"},
         {"decryption", false},
         {"detailed", recorder.detailed()},
         {"stream_capacity", Recorder::stream_capacity},
         {"event_capacity", Recorder::event_capacity},
         {"io_chunk", r.chunk},
         {"tcp_nodelay", true},
         {"perf_counters", c.requested()},
         {"cpu_samples", r.cpu_samples},
         {"ordinary_timing_sample", r.role == r.measured_role && r.purpose == "measurement" &&
                                   r.scenario_complete && !c.requested() && !r.cpu_samples},
         {"counters_file", r.role == r.measured_role ? Json("counters.json") : Json(nullptr)}}},
       {"negotiated",
        {{"version", r.version},
         {"resumed", r.resumed < 0 ? Json(nullptr) : Json(r.resumed != 0)},
         {"profile", static_cast<unsigned>(r.profile)},
         {"record_policy", r.record_policy},
         {"peer_verified", r.peer_verified < 0 ? Json(nullptr) : Json(r.peer_verified == 1)},
         {"cipher", optional(r.cipher, r.version != 0)},
         {"group", optional(r.group, r.version != 0)}}},
       {"scenario",
        {{"complete", r.scenario_complete}, {"name", r.scenario},
         {"observations_complete", r.scenario_observations_complete},
         {"content_verified", r.content_verified}, {"plaintext_received", r.plaintext_received}, {"plaintext_sent", r.plaintext_sent},
         {"begin_event", r.begin_event ? Json(r.begin_event) : Json(nullptr)},
         {"end_event", r.end_event ? Json(r.end_event) : Json(nullptr)},
         {"begin", stamp(r.begin)},
         {"end", stamp(r.end)},
         {"duration", duration(r.begin, r.end)},
         {"tls_send_bytes", recorder.detailed() ? Json(r.scenario_tls_send) : Json(nullptr)},
         {"tls_receive_bytes", recorder.detailed() ? Json(r.scenario_tls_receive) : Json(nullptr)},
         {"wire_send_bytes", recorder.detailed() ? Json(r.scenario_wire_send) : Json(nullptr)},
         {"wire_receive_bytes", recorder.detailed() ? Json(r.scenario_wire_receive) : Json(nullptr)}}},
       {"streams", Json::object()}});
  if (r.role_sdk) {
    out["collection"]["role_contract"] = "pull.v1";
    // Eligibility belongs to offline analysis; the endpoint cannot verify its peer.
    out["collection"]["ordinary_timing_sample"] = nullptr;
    out["collection"]["transport_hooks"] = {{"bound", r.counts_bound},
        {"send_attempts", number(r.send_attempts, r.counts_bound)},
        {"positive_receives", number(r.positive_receives, r.counts_bound)}};
    out["capability"]["client_hello_bytes"] = r.client_hello_bytes;
    out["capability"]["presend_begin"] = r.presend_begin;
  }
  if (recorder.detailed()) for (auto layer : {Layer::tls, Layer::wire})
    for (auto direction : {Direction::receive, Direction::send}) {
      auto key = std::string(layer == Layer::tls ? "tls_" : "wire_") +
                 (direction == Direction::send ? "send" : "receive");
      auto bytes = recorder.stream(layer, direction);
      std::ofstream binary(root / (key + ".bin"), std::ios::binary);
      binary.write(reinterpret_cast<const char *>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
      binary.close();
      if (!binary)
        throw std::runtime_error("stream_write_failed");
      out["streams"][key] = {{"file", key + ".bin"}, {"bytes", bytes.size()}};
    }
  save(root / "endpoint.json", out);
}
} // namespace turtle::artifact
