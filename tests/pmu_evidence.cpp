#include "analysis/analysis.hpp"
#include "artifact/endpoint.hpp"
#include "process/process.hpp"
#include <cerrno>
#include <cstddef>
#include <iostream>
#include <sstream>
#include <thread>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

using turtle::artifact::Json;
namespace fs = std::filesystem;
using namespace turtle;
namespace {
void require(bool ok, const char *why) {
  if (!ok) throw std::runtime_error(why);
}
// Restricts only this test process. The collector receives the same errno as
// on a board that denies the syscall, without modifying a global PMU policy.
bool deny_perf() {
  sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_perf_event_open, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
  sock_fprog program{4, filter};
  return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
         prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}
Json report(const fs::path &dir) {
  analysis::Endpoint ep;
  ep.summary = artifact::load(dir / "endpoint.json");
  auto text = artifact::read_text(dir / "events.jsonl");
  std::istringstream events(text);
  ep.events = Json::array();
  for (std::string line; std::getline(events, line);)
    ep.events.push_back(Json::parse(line));
  return analysis::counters(dir, ep);
}
int run(const std::string &mode, const fs::path &dir) {
  if (mode == "denied" && !deny_perf()) return 77;
  const bool offline = mode == "offline";
  require(mode == "denied" || mode == "live" || offline, "unknown test mode");
  fs::create_directories(dir);
  measure::Recorder rec(3, true, measure::Mode::basic);
  const auto &c = rec.counters();
  if (mode == "live" && c.availability() != measure::PerfAvailability::available) {
    std::cerr << c.reason() << ": errno=" << c.error_number() << '\n';
    return 77;
  }
  artifact::Result result;
  result.role_sdk = true;
  result.role = result.measured_role = "client";
  result.begin_event = result.end_event = rec.begin(measure::Kind::call, measure::Operation::handshake);
  std::uint64_t x = 11;
  for (unsigned i = 0; i < 100000; ++i) x = x * 13 + i;
  result.end = rec.end(result.end_event, true);
  result.begin = rec.event(result.begin_event).begin;
  std::cout << "work=" << x << '\n';
  artifact::write(dir.string(), rec, result);
  auto raw = artifact::load(dir / "counters.json");
  const auto &b = raw.at("scenario").at("begin"), &e = raw.at("scenario").at("end");
  if (mode == "denied") {
    if (raw.at("reason") == "pmu_not_built") return 77;
    auto r = report(dir);
    require(raw.at("reason") == "cycles_open_failed" && raw.at("errno") == EACCES &&
            b.at("cycles").is_null() && e.at("instructions").is_null() &&
            !r.at("complete").get<bool>(), "denial not preserved");
    return 0;
  }
  if (mode == "live") {
    auto r = report(dir);
    require(r.at("complete").get<bool>() && b.at("tid") == raw.at("owner_tid") &&
            e.at("tid") == b.at("tid"), "not continuously scheduled on owner thread");
    const auto &m = r.at("operations").at("scenario");
    for (auto key : {"cycles", "instructions", "time_enabled_ns", "time_running_ns"}) {
      const auto delta = artifact::integer(e.at(key)) - artifact::integer(b.at(key));
      require(delta > 0 && m.at(key).at("value") == delta, "raw delta not reproduced");
    }
    std::cout << m.dump() << '\n';
    measure::PerfCounters owner(true);
    std::thread other([&] { require(!owner.snapshot().available, "wrong thread snapshot accepted"); });
    other.join();
    require(owner.reason() && std::string(owner.reason()) == "counter_thread_mismatch", "wrong thread not identified");
    return 0;
  }
  // Deterministic test vectors, not measurements. Use real clock fields so
  // only the proof being exercised is changed.
  raw["availability"] = "available";
  raw["reason"] = nullptr;
  raw["owner_tid"] = raw.at("tid");
  for (auto edge : {"begin", "end"}) {
    auto &p = raw["scenario"][edge];
    bool end = std::string(edge) == "end";
    p.update({{"available", true}, {"tid", raw.at("tid")},
              {"cycles", end ? 55 : 10}, {"instructions", end ? 100 : 20},
              {"time_enabled_ns", end ? 35 : 5}, {"time_running_ns", end ? 35 : 5},
              {"read_begin_ns", p.at("wall_ns")}, {"read_end_ns", p.at("wall_ns")}});
    raw["events"][0][edge] = p;
  }
  auto check = [&](Json data) {
    artifact::save(dir / "counters.json", data);
    return report(dir);
  };
  require(check(raw).at("complete").get<bool>(), "good raw fixture rejected");
  auto malformed = raw;
  malformed["events"][0]["end"]["tid"] = 0;
  require(check(malformed).at("reason") == "counter_thread_mismatch", "offline tid mismatch");
  malformed = raw;
  malformed["scenario"]["end"]["cycles"] = 56;
  require(check(malformed).at("reason") == "counter_scenario_boundary_mismatch", "boundary substitution");
  for (unsigned running : {5u, 15u}) {
    auto m = raw;
    m["events"][0]["end"]["time_running_ns"] = m["scenario"]["end"]["time_running_ns"] = running;
    const auto r = check(m);
    const auto &scope = r.at("operations").at("scenario");
    require(!r.at("complete").get<bool>() && scope.at("cycles").at("value").is_null() &&
            scope.at("cycles_raw").at("value").is_null() == (running == 5), "partial PMU coverage");
  }
  // Raw inventory validity is independent of TLS task success.
  auto attempt = dir / "inventory";
  fs::create_directories(attempt);
  artifact::write_text(attempt / "raw", "known");
  Json config = {{"measurement_contract", "counts-enough.v1"}, {"scenario", "S0"},
                 {"auth", "server"}, {"measured_role", "client"}, {"recording", "basic"},
                 {"application", Json::object()}};
  Json schedule = {{"run_id", "test"}, {"purpose", "measurement"},
                   {"artifacts_sha256", {{"raw", process::digest(attempt / "raw")}}}};
  auto assessed = [&] { return analysis::assess(attempt, config, schedule); };
  artifact::write_text(attempt / "analysis.json", "{");
  require(assessed().at("raw_evidence_valid").get<bool>(), "damaged derived report blocked intact inventory");
  artifact::write_text(attempt / "analysis.json", "unfinished report");
  artifact::write_text(attempt / "raw", "changed");
  require(!assessed().at("raw_evidence_valid").get<bool>() &&
              artifact::load(attempt / "analysis.json").at("eligible") == false,
          "damaged derived report blocked rejection of damaged raw evidence");
  artifact::write_text(attempt / "raw", "known");
  // Historical decoder status lived in the derived report, not the inventory.
  // A rejected inventory must retain that input without publishing stale rows.
  const Json receipt = {{"returncode", 0}, {"stdout", "perf.script.txt"}};
  auto prior = artifact::load(attempt / "analysis.json");
  prior["roles"]["client"]["cpu_profile"] =
      {{"analysis_command", receipt}, {"sample_count", 1}};
  artifact::save(attempt / "analysis.json", prior);
  artifact::write_text(attempt / "raw", "changed");
  auto changed = assessed();
  require(!changed.at("raw_evidence_valid").get<bool>() && !changed.at("eligible").get<bool>() &&
          changed.at("invalid_reasons")[0] == "raw_artifact_digest_mismatch" &&
          changed.at("measurements").empty(), "corrupt evidence accepted");
  require(changed.at("roles").empty() &&
              changed.at("legacy_decoder_receipts").at("client") ==
                  Json{{"analysis_command", receipt}},
          "rejected attempt lost decoder receipt or retained measurements");
  artifact::write_text(attempt / "raw", "known");
  auto repaired = assessed();
  require(repaired.at("raw_evidence_valid").get<bool>() &&
              repaired.at("legacy_decoder_receipts") ==
                  changed.at("legacy_decoder_receipts"),
          "restoring raw data lost decoder receipt");
  return 0;
}
}
int main(int argc, char **argv) {
  try { return argc == 3 ? run(argv[1], argv[2]) : 1; }
  catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
