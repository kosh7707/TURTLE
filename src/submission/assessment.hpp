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
inline void check_transport(const fs::path &path) {
  CsvInput file(path);
  Record row;
  bool sent = false, received = false;
  while (file.next(row)) {
    auto start = number<uint64_t>(row.at("start_ns")), end = number<uint64_t>(row.at("end_ns"));
    auto requested = number<uint64_t>(row.at("requested"));
    auto written = number<int64_t>(row.at("result"));
    const auto &dir = row.at("direction");
    evidence(start && end >= start && (dir == "send" || dir == "recv") &&
             (written <= 0 || static_cast<uint64_t>(written) <= requested), "invalid transport return");
    if (written > 0) (dir == "send" ? sent : received) = true;
  }
  evidence(sent && received, "missing successful bidirectional transport");
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
    const auto &m = c.role == "server" ? server : client, &p = c.role == "server" ? client : server;
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
    evidence(p.at("wall_status") == "not_collected" && p.at("pmu_status") == "not_collected" &&
             p.at("transport_status") == "not_collected" && p.at("wall_ns").empty() && p.at("cycles").empty() &&
             !fs::exists(base(c.role == "client" ? "server" : "client") + ".transport.csv"),
             "unexpected instrumentation on unmeasured role");
    evidence(m.at("transport_status") == "complete", "continuous transport coverage not confirmed");
    check_transport(base(c.role) + ".transport.csv");
    result.end_event = m.at("end_event");
    evidence(result.end_event == end_event(c.scenario.back(), c.role == "server"), "wrong local timing endpoint");
    result.wall_status = m.at("wall_status");
    if (result.wall_status == "available") {
      evidence(result.end_event != "cf_transport_receive", "unsupported client Finished receipt claim");
      const auto b = number<uint64_t>(m.at("start_ns")), e = number<uint64_t>(m.at("end_ns"));
      evidence(b && e >= b && e-b == number<uint64_t>(m.at("wall_ns")), "invalid role-local elapsed interval");
      result.start = m.at("start_ns"); result.end = m.at("end_ns"); result.wall = m.at("wall_ns");
    } else if (!m.at("wall_ns").empty()) throw std::runtime_error("unexpected unavailable elapsed value");
    result.pmu_status = m.at("pmu_status"); result.pmu_reason = m.at("pmu_reason");
    if (!m.at("cycles").empty()) {
      evidence(!result.wall.empty() && result.pmu_status == "available" &&
               number<uint64_t>(m.at("pmu_running_ns")) > 0 &&
               number<uint64_t>(m.at("pmu_running_ns")) == number<uint64_t>(m.at("pmu_enabled_ns")), "invalid counter interval");
      (void)number<uint64_t>(m.at("cycles")); result.cycles = m.at("cycles");
    }
    if (result.wall.empty()) {
      result.reason = c.scenario == "S2" && c.role == "server" ? "client_finished_transport_receipt_unobserved" : "task_end_unobserved";
    } else result.state = "passed";
  } catch (const std::exception &e) {
    if (result.wall.empty()) result.wall_status = "unavailable";
    if (result.cycles.empty() && (result.pmu_status == "available" || result.pmu_status == "partial")) result.pmu_status = "unavailable";
    result.reason = e.what();
  }
  return result;
}
} // namespace turtle::submission
