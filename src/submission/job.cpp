#include "artifact/json.hpp"
#include "process/process.hpp"
#include "submission/connection_evidence.hpp"
#include "submission/image_receipt.hpp"
#include "submission/process_maps.hpp"
#include <cerrno>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using std::string;
using turtle::artifact::Json;
using turtle::artifact::load;
using turtle::artifact::save;

namespace {
void require(bool test, const string &message) {
  if (!test)
    throw std::runtime_error(message);
}
unsigned number(const string &s) {
  unsigned n = 0;
  auto [end, err] = std::from_chars(s.data(), s.data() + s.size(), n);
  require(err == std::errc{} && end == s.data() + s.size() && n <= 100000,
          "invalid count: " + s);
  return n;
}
std::vector<string> choices(const string &s, const string &all,
                            std::vector<string> values) {
  if (s == all)
    return values;
  for (const auto &v : values)
    if (s == v)
      return {v};
  throw std::runtime_error("invalid selection: " + s);
}
int controller(const fs::path &exe, const fs::path &profile,
               const fs::path &output) {
  pid_t p = fork();
  if (p < 0)
    throw std::runtime_error("fork failed");
  if (p == 0) {
    execl(exe.c_str(), exe.c_str(), "run", profile.c_str(), output.c_str(),
          static_cast<char *>(nullptr));
    _exit(127);
  }
  int status;
  while (waitpid(p, &status, 0) < 0)
    if (errno != EINTR)
      throw std::runtime_error("waitpid failed");
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
std::vector<fs::path> libraries(const fs::path &build) {
  std::ifstream in(build / "expected-libs.txt");
  std::vector<fs::path> result;
  auto prefix = fs::canonical(build / "prefix").string() + "/";
  for (string path; std::getline(in, path);) {
    auto p = fs::canonical(path);
    require(p.string().starts_with(prefix),
            "target outside native prefix: " + path);
    result.push_back(p);
  }
  require(in.eof() && !result.empty(), "missing expected private libraries");
  return result;
}
std::map<string, string> verify_contents(const fs::path &build,
                                        const std::vector<fs::path> &libs) {
  std::ifstream in(build / "expected-libs.sha256");
  std::set<fs::path> pending(libs.begin(), libs.end());
  std::map<string, string> hashes;
  for (string line; std::getline(in, line);) {
    require(line.size() > 66 && line.substr(64, 2) == "  ",
            "invalid private library digest record");
    fs::path path = line.substr(66);
    const auto hash = line.substr(0, 64);
    require(pending.erase(path) == 1 && turtle::process::digest(path) == hash,
            "private library differs from linked artifact: " + path.string());
    hashes.emplace(path.string(), hash);
  }
  require(in.eof() && pending.empty(), "missing private library digests");
  return hashes;
}
struct Case {
  string role, scenario, auth;
  string peer() const { return role == "client" ? "server" : "client"; }
};

void issue(Json &evidence, std::string_view state, string reason) {
  evidence["issues"].push_back({{"state", state}, {"reason", std::move(reason)}});
  if (evidence["state"] == "passed" || state == "failed")
    evidence["state"] = state;
}

struct Job {
  fs::path exe, build;
  std::vector<fs::path> libs;
  std::map<string, string> lib_hashes;
  string credentials;
  unsigned warmups, repetitions;
  std::set<string> connections;

  Json connection(const Json &row, const fs::path &out, const Case &c,
                  const Json &manifest, size_t index, bool doctor) {
    const auto &events = out / "events";
    const auto &id = row.at("connection_id").get_ref<const string &>();
    const auto &purpose = row.at("purpose");
    const string name = "attempt-" + std::to_string(index + 1);
    const auto attempt = out / "result" / name;
    Json e = {{"connection_id", id},
              {"run_id", manifest.at("run_id")},
              {"purpose", doctor ? Json("doctor") : purpose},
              {"controller_purpose", purpose},
              {"attempt_directory", attempt.string()},
              {"controller_wall_ns", row.at("benchmark_timing_ns")},
              {"controller_qualification", row.at("qualification")},
              {"state", "passed"},
              {"issues", Json::array()},
              {"operational", false},
              {"verified", false}};
    if (id.size() != 36 || id.find_first_not_of("0123456789abcdef-") != id.npos ||
        !connections.insert(id).second || row.at("directory") != name ||
        purpose != (!doctor && index < warmups ? "warmup" : "sample")) {
      issue(e, "insufficient_evidence", "invalid attempt phase or reused connection ID");
      return e;
    }
    const auto raw = load(attempt / "attempt.json");
    if (raw.at("connection_id") != id || raw.at("run_id") != manifest.at("run_id") ||
        raw.at("purpose") != purpose) {
      issue(e, "insufficient_evidence", "attempt did not match controller report");
      return e;
    }
    e["endpoint_results"] = raw.at("exit");
    e["endpoint_pids"] = raw.value("pid", Json::object());
    e["attempt_error"] = raw.at("error");
    for (const auto &side : {c.role, c.peer()})
      e["role_stderr"][side] = (attempt / (side + ".stderr")).string();
    if (row.at("scenario_support") == "unsupported") {
      issue(e, "unsupported", "a role reported an unsupported TLS operation");
      return e;
    }
    const auto &participants = row.at("participants");
    if (!raw.at("error").is_null() || raw.at("exit").at("client") != 0 ||
        raw.at("exit").at("server") != 0 ||
        participants.at("client").at("status") == "contradicted" ||
        participants.at("server").at("status") == "contradicted" ||
        row.at("application_exchange") == "failed")
      issue(e, "failed", "native attempt or peer exchange failed; see attempt.json and role stderr");
    else if (row.at("task_success") != true)
      issue(e, "insufficient_evidence", "controller did not verify both endpoint tasks");
    if (row.at("task_success") != true)
      return e;

    const auto images = raw.value("images", Json(nullptr));
    for (const auto &side : {c.role, c.peer()}) {
      const auto path = events / (id + "." + side + ".maps");
      const auto endpoint = build / "bin" / side;
      using turtle::submission::MapsState;
      const auto maps = turtle::submission::process_maps(path, endpoint, libs);
      e["executables"][side] = endpoint.string();
      e["maps"][side] = path.string();
      e["private_libraries_loaded"][side] = maps == MapsState::matched;
      if (maps == MapsState::contradicted)
        issue(e, "failed", side + ": endpoint or private libraries contradicted by maps");
      else if (maps == MapsState::unavailable)
        issue(e, "insufficient_evidence", side + ": process maps missing or unreadable");
      else if (maps == MapsState::incomplete)
        issue(e, "insufficient_evidence", side + ": process maps incomplete or malformed");
      auto prepared = turtle::submission::prepared_image(
          images.is_object() ? images.value(side, Json(nullptr)) : images,
          raw.at("pid").at(side).get<pid_t>(),
          endpoint.string(), raw.at("binary_sha256").at(side).get_ref<const string &>(),
          lib_hashes);
      const auto &state = prepared.at("state");
      if (state == "contradicted" || state == "invalid")
        issue(e, state == "contradicted" ? "failed" : "insufficient_evidence",
              side + ": " + prepared.at("reason").get<string>());
      e["prepared_images"][side] = std::move(prepared);
    }
    const auto &dut = participants.at(c.role);
    const auto transport = events / (id + "." + c.role + ".csv");
    const auto count = transport.string() + ".count";
    e["transport_csv"] = transport.string();
    e["transport_count"] = count;
    try {
      require(!fs::exists(transport.string() + ".partial") &&
                  !fs::exists(count + ".partial"),
              c.role + ": incomplete transport trace publication; see role_stderr");
      const auto &cad = dut.at("timeline").at("CAD");
      std::ifstream in(transport);
      std::ifstream rows(count);
      require(bool(in), c.role + ": transport trace unavailable; see role_stderr");
      e["transport"] = turtle::submission::read_transport(
          in, rows, c.role, dut.at("lifecycle").at("hs_complete"),
          c.role == "server" && cad.is_object() ? cad.at("last_read_return")
                                               : Json(nullptr));
    } catch (const std::exception &error) {
      issue(e, "insufficient_evidence", error.what());
    }
    const auto peer_csv = events / (id + "." + c.peer() + ".csv");
    e["peer_transport_trace_absent"] = !fs::exists(peer_csv) &&
        !fs::exists(peer_csv.string() + ".partial") &&
        !fs::exists(peer_csv.string() + ".count") &&
        !fs::exists(peer_csv.string() + ".count.partial");
    if (e["peer_transport_trace_absent"] != true)
      issue(e, "failed", "unexpected transport trace or count for non-measured peer");
    const auto &peer_events = participants.at(c.peer()).at("events");
    bool pmu_disabled = !peer_events.empty();
    bool no_peer_sdk_hook = true;
    for (const auto &event : peer_events) {
      pmu_disabled &= event.at("pmu").is_null() &&
                      event.at("pmu_status") == "not_collected";
      const auto &kind = event.at("kind");
      const auto name = event.value("name", string{});
      no_peer_sdk_hook &= kind != "bytes" && kind != "io" && kind != "header" &&
                          kind != "coverage" && name != "local_finished_message" &&
                          name != "peer_finished_message";
    }
    e["peer_sdk_hook_absent"] = no_peer_sdk_hook && !peer_events.empty();
    if (!no_peer_sdk_hook)
      issue(e, "failed", "unexpected SDK hook evidence for non-measured peer");
    e["peer_pmu_not_collected"] = pmu_disabled;
    if (!pmu_disabled)
      issue(e, peer_events.empty() ? "insufficient_evidence" : "failed",
            "peer PMU exclusion was not verified");
    e["operational"] = e.at("state") == "passed";

    const auto &timing = dut.at("timing");
    e["sdk_application_interval"] =
        turtle::submission::sdk_application_interval(timing, c.role);
    e["pmu"] = {{"status", row.at("pmu_status")},
                {"delta", timing.at("pmu_delta")},
                {"counter_window", "native_sdk_application_interval"},
                {"clock_for_window", "CLOCK_MONOTONIC"},
                {"cycle_unit", "cpu_cycle"},
                {"begin", timing.at("begin")},
                {"end", timing.at("end")},
                {"controller_qualified", row.at("qualified")}};
    try {
      e["application"] = turtle::submission::app_evidence(
          participants, c.scenario, c.auth, manifest.at("profile").at("application"),
          c.role);
      const auto &app = e.at("application");
      if (app.at("state") != "passed")
        issue(e, app.at("state").get_ref<const string &>(),
              "application or session checks not proven; see application.issues");
    } catch (const std::exception &error) {
      issue(e, "insufficient_evidence", error.what());
    }
    if (c.scenario == "S1" && c.role == "server" && e.contains("transport") &&
        (e.at("transport").at("cad_receive_boundary").is_null() ||
         e.at("transport").at("cad_receive_boundary").at("candidate").is_null()))
      issue(e, "insufficient_evidence", "no receive hook between server handshake and CAD full read");
    e["verified"] = e.at("state") == "passed";
    return e;
  }

  Json phase(const fs::path &out, const Case &c, bool doctor) {
    const auto events = out / "events";
    fs::create_directories(events);
    auto participant = [&](const string &r, bool measure) {
      return Json{{"argv", Json::array({(build / "bin" / r).string(), "{host}",
                                        "{port}", events.string(),
                                        measure ? "measured" : "peer"})}};
    };
    Json profile = {{"v", 1},
                    {"target", participant(c.role, true)},
                    {"peer", participant(c.peer(), false)},
                    {"scenario", c.scenario},
                    {"auth", c.auth},
                    {"warmups", doctor ? 0 : warmups},
                    {"repetitions", doctor ? 1 : repetitions},
                    {"required_metrics", {"peer_task"}},
                    {"optional_metrics", {"timing", "pmu"}}};
    profile["target"]["role"] = c.role;
    if (!credentials.empty()) {
      fs::path keys(credentials);
      Json leaf = {{"ca", (keys / "ca.crt").string()},
                {"server",
                 {{"cert", (keys / "server.crt").string()},
                  {"key", (keys / "server.key").string()}}}};
      if (c.auth == "mtls")
        leaf["client"] = {{"cert", (keys / "client.crt").string()},
                       {"key", (keys / "client.key").string()}};
      profile["credentials"] = std::move(leaf);
    }
    save(out / "profile.json", profile);
    int rc = controller(exe, out / "profile.json", out / "result");
    Json r = {{"controller_exit", rc},
              {"ready", false},
              {"state", "failed"},
              {"evidence", Json::array()},
              {"analysis", (out / "result" / "analysis.json").string()}};
    if (!fs::is_regular_file(out / "result" / "analysis.json")) {
      r["state"] = rc == 0 ? "insufficient_evidence" : "failed";
      r["reason"] = "controller produced no analysis.json";
      return r;
    }
    const auto report = load(out / "result" / "analysis.json");
    if (report.at("attempts").empty()) {
      r["reason"] = report.value("error", string("controller produced no attempts"));
      return r;
    }
    const auto manifest = load(out / "result" / "manifest.json");
    const auto &recorded = manifest.at("profile");
    require(recorded.at("target").at("role") == c.role &&
                recorded.at("scenario") == c.scenario &&
                recorded.at("auth") == c.auth,
            "controller selected a different role/scenario/auth");
    const unsigned wanted = doctor ? 1 : repetitions;
    bool controller_ok = rc == 0 && report.at("complete") == true &&
                         report.at("successful_measurements") == wanted;
    bool unsupported = false, failure = false;
    unsigned operational = 0, verified = 0, verified_connections = 0;
    size_t index = 0;
    for (const auto &row : report.at("attempts")) {
      auto e = connection(row, out, c, manifest, index++, doctor);
      unsupported |= e.at("state") == "unsupported";
      failure |= e.at("state") == "failed";
      verified_connections += e.at("verified") == true;
      if (row.at("purpose") == "sample") {
        operational += e.at("operational") == true;
        verified += e.at("verified") == true;
      }
      r["evidence"].push_back(std::move(e));
    }
    r["task_successes"] = report.at("successful_measurements");
    r["qualified_controller_samples"] = doctor ? Json(0) : report.at("qualified_samples");
    r["runtime_verified_samples"] = doctor ? 0 : operational;
    r["verified_connections"] = verified_connections;
    r["verified_samples"] = doctor ? 0 : verified;
    r["ready"] = controller_ok && operational == wanted && !failure;
    r["state"] = controller_ok && verified == wanted && !failure ? "passed"
                 : failure                                    ? "failed"
                 : unsupported                                ? "unsupported"
                                                              : "insufficient_evidence";
    return r;
  }
};
} // namespace

int main(int argc, char **argv) {
  try {
    require(argc == 9, "expected controller job role scenario auth warmups "
                       "repetitions credentials");
    auto dir = fs::canonical(argv[2]);
    Job job{fs::canonical(argv[1]),   dir / "build",
            libraries(dir / "build"), {}, argv[8], number(argv[6]),
            number(argv[7]), {}};
    require(job.repetitions > 0, "repetitions must be positive");
    job.lib_hashes = verify_contents(job.build, job.libs);
    Json result = {{"schema", "turtle.submission-run.v2"},
                   {"cases", Json::array()},
                   {"target_libraries", Json::array()}};
    for (const auto &lib : job.libs)
      result["target_libraries"].push_back(lib.string());
    bool ok = true, runtime_ok = true;
    for (const auto &auth : choices(argv[5], "both", {"server", "mtls"}))
      for (const auto &scenario :
           choices(argv[4], "all", {"S0", "S1", "S2", "S3", "S4"}))
        for (const auto &role :
             choices(argv[3], "both", {"client", "server"})) {
          auto out = dir / "runs" / (auth + "-" + scenario + "-" + role);
          require(!fs::exists(out),
                  "case output already exists: " + out.string());
          Json item = {{"auth", auth}, {"scenario", scenario}, {"role", role}};
          const Case selection{role, scenario, auth};
          item["doctor"] = job.phase(out / "doctor", selection, true);
          if (item["doctor"]["ready"] == true)
            item["benchmark"] = job.phase(out / "benchmark", selection, false);
          item["state"] = item.contains("benchmark")
                              ? item["benchmark"]["state"]
                              : item["doctor"]["state"];
          ok &= item["state"] == "passed";
          runtime_ok &= item.contains("benchmark") && item["benchmark"]["ready"] == true;
          std::cout << auth << ' ' << scenario << ' ' << role << ": "
                    << item["state"].get<string>() << '\n';
          result["cases"].push_back(item);
          result["complete"] = false;
          save(dir / "summary.json", result);
        }
    require(verify_contents(job.build, job.libs) == job.lib_hashes,
            "private library digest records changed during the job");
    result["library_hash_check"] = "matched_before_and_after_run";
    result["runtime_complete"] = runtime_ok;
    result["complete"] = ok;
    save(dir / "summary.json", result);
    std::cout << "Results: " << dir / "summary.json" << '\n';
    return ok ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "submission job: " << e.what() << '\n';
    return 1;
  }
}
