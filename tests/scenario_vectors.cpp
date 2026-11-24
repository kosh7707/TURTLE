// Deterministic S4 plaintext replay: these timestamps are a unit vector, not
// measurements or PMU evidence. Exercise the same persisted-event decoder.
#include "analysis/analysis.hpp"
#include <filesystem>
#include <iostream>
#include <vector>

namespace {
using turtle::artifact::Json;
using turtle::artifact::save;
namespace fs = std::filesystem;
Json stamp(unsigned ns) { return {{"wall_ns", ns}, {"thread_cpu_ns", ns}}; }
void check(bool ok, const std::string &why) {
  if (!ok)
    throw std::runtime_error(why);
}
void replay(const fs::path &dir,
            const std::vector<std::pair<std::string, unsigned>> &reads,
            unsigned expected_read) {
  const Json config = {
      {"id", "vector"},
      {"scenario", "S4"},
      {"auth", "mtls"},
      {"measured_role", "client"},
      {"recording", "basic"},
      {"required_metrics", {"scenario_wall_ns"}},
      {"application",
       {{"request", "ping"}, {"greeting", "helo"}, {"response", "pong"}}}};
  const Json slot = {{"purpose", "measurement"},
                     {"configuration", "vector"},
                     {"run_id", "vector"}};
  fs::create_directories(dir / "client");
  fs::create_directories(dir / "server");
  save(dir / "processes.json",
       {{"run_id", "vector"},
        {"error", nullptr},
        {"returncodes", {{"client", 0}, {"server", 0}}}});
  Json events = Json::array();
  auto add = [&](const char *op, unsigned begin, unsigned end, size_t low = 0,
                 size_t high = 0) {
    events.push_back({{"schema", "turtle.event.v2"},
                      {"id", events.size() + 1},
                      {"role", "client"},
                      {"run_id", "vector"},
                      {"connection_id", "vector"},
                      {"kind", "call"},
                      {"operation", op},
                      {"parent", 0},
                      {"success", true},
                      {"begin", stamp(begin)},
                      {"end", stamp(end)},
                      {"plaintext_begin", low},
                      {"plaintext_end", high},
                      {"transferred", high - low}});
    return events.size();
  };
  add("handshake", 1000, 1100);
  add("application_write", 1110, 1200, 0,
      4); // CAD is permitted before the greeting arrives.
  std::string plaintext;
  std::vector<size_t> ids;
  for (const auto &[bytes, end] : reads) {
    size_t low = plaintext.size();
    plaintext += bytes;
    ids.push_back(
        add("application_read", end - 10, end, low, plaintext.size()));
    if (low < 4 && plaintext.size() >= 4)
      add("content_verify", end + 1, end + 2, 0, 4);
  }
  check(plaintext == "helopong", "bad S4 fixture");
  add("content_verify", 2140, 2150, 4, 8);
  const size_t first = ids.at(expected_read);
  const unsigned first_ns = reads.at(expected_read).second;
  Json prop = {{"availability", "available"}, {"value", "X25519"}};
  for (bool client : {true, false}) {
    const char *role = client ? "client" : "server";
    save(dir / role / "endpoint.json",
         {{"schema", "turtle.endpoint.v4"},
          {"run_id", "vector"},
          {"connection_id", "vector"},
          {"role", role},
          {"auth", "mtls"},
          {"purpose", "measurement"},
          {"measured_role", "client"},
          {"status", "ok"},
          {"recording", "basic"},
          {"shutdown", "ok"},
          {"implementation", "timestamp fixture"},
          {"streams", Json::object()},
          {"collection",
           {{"role_contract", "pull.v1"},
            {"framing", "none"},
            {"perf_counters", false}}},
          {"negotiated",
           {{"version", 772},
            {"profile", 2},
            {"resumed", false},
            {"peer_verified", true},
            {"cipher",
             {{"availability", "available"},
              {"value", "TLS_AES_128_GCM_SHA256"}}},
            {"group", prop}}},
          {"scenario",
           {{"name", "S4"},
            {"complete", true},
            {"content_verified", true},
            {"plaintext_sent", client ? 4 : 8},
            {"plaintext_received", client ? 8 : 4},
            {"begin_event", 1},
            {"end_event", first},
            {"begin", stamp(1000)},
            {"end", stamp(first_ns)}}}});
  }
  std::string lines;
  for (const auto &event : events)
    lines += event.dump() + "\n";
  turtle::artifact::write_text(dir / "client/events.jsonl", lines);
  auto r = turtle::analysis::assess(dir, config, slot);
  check(r.at("success") == true && r.at("eligible") == true,
        r.at("invalid_reasons").dump());
  const auto &metrics = r.at("roles").at("client").at("metrics");
  auto point = metrics.at("first_response_wall_ns");
  check(point.at("end_event") == first && point.at("value") == first_ns - 1000,
        "wrong first response read");
  check(metrics.at("response_verified_wall_ns").at("value") == 1150,
        "wrong full verification");
  check(metrics.at("first_greeting_wall_ns").at("end_event") == ids.front(),
        "wrong first greeting read");
}
} // namespace
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      return 2;
    const fs::path root(argv[1]);
    replay(root / "fragmented",
           {{"he", 1500}, {"lo", 1600}, {"po", 1900}, {"ng", 2100}}, 2);
    replay(root / "crossing", {{"hel", 1500}, {"op", 1900}, {"ong", 2100}}, 1);
    replay(root / "coalesced", {{"helopong", 1900}}, 0);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
