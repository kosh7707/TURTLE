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
  case Kind::frame:
    return "frame";
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
      {{"schema", "turtle.counters.v1"},
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
  std::ofstream events(root / "events.jsonl");
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
    events << j.dump() << '\n';
  }
  events.close();
  if (!events)
    throw std::runtime_error("events_write_failed");
  save(root / "counters.json", counters);
  Json out = identity;
  out.update(
      {{"schema", "turtle.endpoint.v3"},
       {"connection_id", r.connection_id},
       {"implementation", r.implementation},
       {"status", r.scenario_complete && r.scenario_observations_complete
                      ? "ok"
                      : "invalid"},
       {"invalid_reason",
        r.invalid_reason.empty() ? Json(nullptr) : Json(r.invalid_reason)},
       {"observation_reason", r.observation_reason.empty()
                                  ? Json(nullptr)
                                  : Json(r.observation_reason)},
       {"shutdown", r.shutdown},
       {"observations_complete", recorder.complete()},
       {"clock",
        {{"wall", "CLOCK_MONOTONIC"}, {"cpu", "CLOCK_THREAD_CPUTIME_ID"}}},
       {"collection",
        {{"framing", "TU-u16be"},
         {"decryption", false},
         {"message_callbacks", false},
         {"stream_capacity", Recorder::stream_capacity},
         {"event_capacity", Recorder::event_capacity},
         {"io_chunk", r.chunk},
         {"tcp_nodelay", true},
         {"perf_counters", c.requested()},
         {"cpu_samples", r.cpu_samples},
         {"ordinary_timing_sample", !c.requested() && !r.cpu_samples},
         {"counters_file", "counters.json"}}},
       {"negotiated",
        {{"version", r.version},
         {"resumed", r.resumed < 0 ? Json(nullptr) : Json(r.resumed != 0)},
         {"profile", static_cast<unsigned>(r.profile)},
         {"cipher", optional(r.cipher, r.version != 0)},
         {"group", optional(r.group, r.version != 0)}}},
       {"scenario",
        {{"complete", r.scenario_complete},
         {"begin", stamp(r.begin)},
         {"end", stamp(r.end)},
         {"duration", duration(r.begin, r.end)},
         {"tls_send_bytes", r.scenario_tls_send},
         {"tls_receive_bytes", r.scenario_tls_receive},
         {"wire_send_bytes", r.scenario_wire_send},
         {"wire_receive_bytes", r.scenario_wire_receive}}},
       {"streams", Json::object()}});
  for (auto layer : {Layer::tls, Layer::wire})
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
