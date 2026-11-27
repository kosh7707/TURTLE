#pragma once
#include "submission/csv.hpp"
#include "submission/endpoints.hpp"
#include <cstdlib>
#include "submission/process_maps.hpp"
#include <cstdint>
#include <sys/types.h>
#include <string>

namespace turtle::submission {
namespace fs = std::filesystem;
struct Case {
  std::string auth, scenario, role;
  std::string name() const { return auth + "-" + scenario + "-" + role; }
};
struct Result {
  std::string state = "insufficient_evidence", reason, task_success, wall, wall_status = "unavailable",
              cycles, pmu_status = "unavailable", pmu_reason, start, end, end_event;
};
inline void evidence(bool ok, const std::string &message) {
  if (!ok) throw std::runtime_error(message);
}
inline void check_application(const fs::path &path, const std::string &scenario, bool server) {
  const bool greet = scenario == "S2" || scenario == "S4";
  const bool reply = scenario == "S3" || scenario == "S4";
  const bool request = scenario == "S1" || reply;
  const std::string cad = "70696e67", sad1 = "68656c6c6f", sad2 = "706f6e67";
  const std::string from_client = request ? cad : "";
  const std::string from_server = (greet ? sad1 : "") + (reply ? sad2 : "");
  CsvInput file(path);
  bool hs = false, verified_request = false, first_reply = false;
  std::string writes, reads, verified;
  Record row;
  while (file.next(row)) {
    const auto &event = row.at("event"), &msg = row.at("message");
    if (event == "handshake_complete") { evidence(!hs, "duplicate handshake completion"); hs = true; continue; }
    const auto &hex = row.at("hex");
    evidence(hex.size() % 2 == 0 && hex.size()/2 == number<size_t>(row.at("bytes")), "invalid application byte count");
    if (event == "write_attempt" && server && msg == "SAD2") {
      evidence(hs && verified_request, "server offered reply before handshake or request validation");
      first_reply = true;
    } else if (event == "write_accepted") {
      if (server && msg == "SAD2") evidence(first_reply, "missing reply offer");
      writes += hex;
    } else if (event == "read_return") reads += hex;
    else if (event == "validated") {
      verified += hex;
      if (server && msg == "CAD" && hex == cad) verified_request = true;
    }
  }
  evidence(hs && writes == (server ? from_server : from_client) &&
           reads == (server ? from_client : from_server) && verified == reads, "application transcript mismatch");
  if (server && reply) evidence(first_reply, "missing gated server reply");
}
inline uint64_t check_transport(const fs::path &path, uint64_t cf_record_end = 0) {
  CsvInput file(path);
  Record row;
  bool sent = false, received = false;
  uint64_t received_bytes = 0, receipt_time = 0, last_end = 0;
  while (file.next(row)) {
    auto start = number<uint64_t>(row.at("start_ns")), end = number<uint64_t>(row.at("end_ns"));
    auto requested = number<uint64_t>(row.at("requested"));
    auto written = number<int64_t>(row.at("result"));
    const auto &dir = row.at("direction");
    const auto &mark = row.at("cf_record_end");
    evidence(start && end >= start && (dir == "send" || dir == "recv") &&
             (written <= 0 || static_cast<uint64_t>(written) <= requested), "invalid transport return");
    if (cf_record_end) {
      evidence(last_end <= end, "non-monotonic client Finished transport trace");
      last_end = end;
    }
    if (!mark.empty())
      evidence(cf_record_end && !receipt_time && written > 0 && dir == "recv" &&
               number<uint64_t>(mark) == cf_record_end, "invalid client Finished transport marker");
    if (written <= 0) continue;
    if (dir == "send") {
      sent = true;
    } else {
      received = true;
      if (!cf_record_end) continue;
      const auto bytes = static_cast<uint64_t>(written);
      evidence(bytes <= UINT64_MAX - received_bytes, "transport receive offset overflow");
      const auto after = received_bytes + bytes;
      if (!mark.empty()) {
        evidence(received_bytes < cf_record_end && cf_record_end <= after,
                 "client Finished offset outside marked transport return");
        receipt_time = end;
      }
      received_bytes = after;
    }
  }
  evidence(sent && received, "missing successful bidirectional transport");
  return receipt_time;
}

inline void assess_measurement(const Case &c, const Record &measured,
                               const fs::path &transport_path, Result &result) {
  evidence(measured.at("transport_status") == "complete", "continuous transport coverage not confirmed");
  result.end_event = measured.at("end_event");
  const bool server = c.role == "server";
  evidence(result.end_event == end_event(c.scenario.back(), server), "wrong local timing endpoint");

  const bool needs_finished_receipt = server && c.scenario == "S2";
  const auto &record_end = measured.at("cf_record_end");
  uint64_t receipt_offset = 0;
  if (needs_finished_receipt && measured.at("wall_status") == "available") {
    receipt_offset = number<uint64_t>(record_end);
    evidence(receipt_offset != 0, "invalid client Finished record offset");
  } else {
    evidence(record_end.empty() && (!needs_finished_receipt || measured.at("end_ns").empty()),
             "unexpected client Finished receipt evidence");
  }
  const auto receipt_time = check_transport(transport_path, receipt_offset);

  result.wall_status = measured.at("wall_status");
  if (result.wall_status == "available") {
    const auto start = number<uint64_t>(measured.at("start_ns"));
    const auto end = number<uint64_t>(measured.at("end_ns"));
    evidence(start && end >= start && end - start == number<uint64_t>(measured.at("wall_ns")),
             "invalid role-local elapsed interval");
    if (needs_finished_receipt)
      evidence(receipt_time && receipt_time == end, "client Finished record does not match transport return");
    result.start = measured.at("start_ns");
    result.end = measured.at("end_ns");
    result.wall = measured.at("wall_ns");
  } else if (!measured.at("wall_ns").empty()) {
    throw std::runtime_error("unexpected unavailable elapsed value");
  }

  // A rejected counter must not erase an already verified wall interval.
  result.pmu_status = measured.at("pmu_status");
  result.pmu_reason = measured.at("pmu_reason");
  const auto &cycles = measured.at("cycles");
  if (!cycles.empty()) {
    evidence(!result.wall.empty() && result.pmu_status == "available" &&
             number<uint64_t>(measured.at("pmu_running_ns")) > 0 &&
             number<uint64_t>(measured.at("pmu_running_ns")) == number<uint64_t>(measured.at("pmu_enabled_ns")),
             "invalid counter interval");
    (void)number<uint64_t>(cycles);
    result.cycles = cycles;
  }
  if (result.wall.empty())
    result.reason = needs_finished_receipt ? "client_finished_transport_receipt_unobserved" : "task_end_unobserved";
  else
    result.state = "passed";
}

inline Result assess(const Case &c, const fs::path &dir, const std::string &id,
                     const fs::path &build, const std::vector<fs::path> &libs,
                     pid_t client_pid, pid_t server_pid) {
  Result result;
  try {
    const auto base = [&](std::string side) { return (dir / (id + "." + side)).string(); };
    const auto client = read_role(base("client") + ".csv"), server = read_role(base("server") + ".csv");
    const auto &cs = client.at("status"), &ss = server.at("status");
    if (cs != "passed" || ss != "passed") {
      result.state = cs == "unsupported" || ss == "unsupported" ? "unsupported" :
                     cs == "unavailable" || ss == "unavailable" ? "insufficient_evidence" : "failed";
      result.task_success = "0";
      result.reason = "client:" + cs + ":" + client.at("reason") + "; server:" + ss + ":" + server.at("reason");
      return result;
    }
    check_application(base("client") + ".app.csv", c.scenario, false);
    check_application(base("server") + ".app.csv", c.scenario, true);
    result.task_success = "1";
    evidence(number<pid_t>(client.at("pid")) == client_pid && number<pid_t>(server.at("pid")) == server_pid,
             "role PID changed");
    evidence(client.at("remote_port") == server.at("local_port") && client.at("local_port") == server.at("remote_port") &&
             number<unsigned>(client.at("local_port")) > 0 && number<unsigned>(server.at("local_port")) > 0, "unmatched TCP connection");
    const std::string tcp = std::getenv("TURTLE_TCP_NODELAY") && std::string_view(std::getenv("TURTLE_TCP_NODELAY")) == "off" ? "0" : "1";
    evidence(client.at("tcp_nodelay") == tcp && server.at("tcp_nodelay") == tcp, "socket TCP_NODELAY mismatch");
    for (const auto &side : {"client","server"}) {
      const auto &r = std::string_view(side) == "client" ? client : server;
      evidence(process_maps(base(side) + ".maps", build / "bin" / side, libs) == MapsState::matched, "linked library not verified in role maps");
      evidence(r.at("tls13") == "1" && r.at("resumed") == "0" && r.at("early_data") == "0", "fresh TLS 1.3 session not confirmed");
      if (std::string_view(side) == "client" || c.auth == "mtls")
        evidence(r.at("peer_cert_present") == "1" && r.at("peer_verified") == "1", "peer authentication not confirmed");
    }
    if (c.scenario == "S2" || c.scenario == "S4")
      evidence(server.at("server_first") == "1", "server-first greeting path not confirmed");
    const auto &peer = c.role == "server" ? client : server;
    evidence(peer.at("wall_status") == "not_collected" && peer.at("pmu_status") == "not_collected" &&
             peer.at("transport_status") == "not_collected" && peer.at("wall_ns").empty() && peer.at("cycles").empty() &&
             peer.at("start_ns").empty() && peer.at("end_ns").empty() && peer.at("cf_record_end").empty() &&
             !fs::exists(base(c.role == "client" ? "server" : "client") + ".transport.csv"),
             "unexpected instrumentation on unmeasured role");
    const auto &measured = c.role == "server" ? server : client;
    assess_measurement(c, measured, base(c.role) + ".transport.csv", result);
  } catch (const std::exception &e) {
    if (result.wall.empty()) result.wall_status = "unavailable";
    if (result.cycles.empty() && (result.pmu_status == "available" || result.pmu_status == "partial")) result.pmu_status = "unavailable";
    result.reason = e.what();
  }
  return result;
}
} // namespace turtle::submission
