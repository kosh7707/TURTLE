#include "artifact/json.hpp"
#include "process/process.hpp"
#include "submission/connection_evidence.hpp"
#include "submission/image_receipt.hpp"
#include "submission/process_maps.hpp"
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <signal.h>
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
struct Interrupted {
  int signal;
};

// The launcher execs this process. Wait for either the exact owned child
// or a stop request without checking a flag and then blocking on a race.
class Supervisor {
  sigset_t stops_{}, child_mask_{};

public:
  Supervisor() {
    sigemptyset(&stops_);
    sigaddset(&stops_, SIGTERM);
    sigaddset(&stops_, SIGINT);
    require(sigprocmask(SIG_BLOCK, &stops_, &child_mask_) == 0,
            "could not block submission stop signals");
    for (int sig : {SIGTERM, SIGINT, SIGCHLD}) {
      require(signal(sig, SIG_DFL) != SIG_ERR, "could not initialize child supervision");
      sigdelset(&child_mask_, sig);
    }
  }

  void check() const {
    timespec immediate{};
    int sig;
    do {
      sig = sigtimedwait(&stops_, nullptr, &immediate);
    } while (sig < 0 && errno == EINTR);
    if (sig > 0)
      throw Interrupted{sig};
    require(errno == EAGAIN, "could not check submission stop signals");
  }

  int run(const turtle::process::Args &args) const {
    auto changes = stops_;
    sigaddset(&changes, SIGCHLD);
    struct RestoreMask {
      sigset_t mask;
      ~RestoreMask() { sigprocmask(SIG_SETMASK, &mask, nullptr); }
    } old{};
    require(sigprocmask(SIG_BLOCK, &changes, &old.mask) == 0,
            "could not block child exit signal");
    check();
    std::vector<char *> argv;
    for (const auto &arg : args)
      argv.push_back(const_cast<char *>(arg.c_str()));
    argv.push_back(nullptr);
    const pid_t child = fork();
    if (child < 0)
      throw std::runtime_error("fork failed");
    if (child == 0) {
      if (sigprocmask(SIG_SETMASK, &child_mask_, nullptr) == 0)
        execv(argv[0], argv.data());
      _exit(127);
    }
    int requested = 0, status = 0;
    for (;;) {
      const auto finished = waitpid(child, &status, WNOHANG);
      if (finished == child)
        break;
      if (finished < 0) {
        if (errno == EINTR)
          continue;
        throw std::runtime_error("waitpid failed");
      }
      const int sig = sigwaitinfo(&changes, nullptr);
      if ((sig == SIGTERM || sig == SIGINT) && !requested) {
        requested = sig;
        // The controller owns its endpoint children and their cleanup.
        kill(child, SIGTERM);
      }
    }
    if (requested)
      throw Interrupted{requested};
    check();
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  }
};

Supervisor &supervisor() {
  static Supervisor instance;
  return instance;
}

int controller(const fs::path &exe, const fs::path &profile,
               const fs::path &output) {
  return supervisor().run({exe.string(), "run", profile.string(), output.string()});
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
  fs::path exe, build, observer;
  std::vector<fs::path> libs;
  std::map<string, string> lib_hashes;
  string credentials;
  unsigned warmups, repetitions;
  bool tcp_nodelay;
  std::set<string> connections;

  Json connection(const Json &row, const fs::path &out, const Case &c,
                  const Json &summary, size_t index, bool doctor) {
    const auto &events = out / "events";
    const auto &id = row.at("connection_id").get_ref<const string &>();
    const auto &purpose = row.at("purpose");
    const string name = "attempt-" + std::to_string(index + 1);
    const auto attempt = out / "result" / name;
    require(id.size() == 36 && id.find_first_not_of("0123456789abcdef-") == id.npos &&
                row.at("directory") == name &&
                purpose == (!doctor && index < warmups ? "warmup" : "sample") &&
                connections.insert(id).second,
            "invalid attempt phase or reused connection ID");
    const auto raw_path = attempt / "attempt.json";
    require(fs::is_regular_file(fs::symlink_status(raw_path)), "missing or invalid attempt.json");
    const auto raw = load(raw_path);
    require(raw.at("connection_id") == id && raw.at("run_id") == summary.at("run_id") &&
                raw.at("purpose") == purpose,
            "attempt did not match controller report");
    Json e = {{"connection_id", id},
              {"run_id", summary.at("run_id")},
              {"purpose", doctor ? Json("doctor") : purpose},
              {"controller_purpose", purpose},
              {"attempt_directory", attempt.string()},
              {"task_success", row.at("task_success")},
              {"controller_qualification", row.at("qualification")},
              {"tcp_nodelay", Json::object()},
              {"state", "passed"},
              {"issues", Json::array()},
              {"operational", false},
              {"verified", false}};
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
      const auto &endpoint_facts = participants.at(side).at("facts");
      const auto effective = endpoint_facts.value("tcp_nodelay", Json(nullptr));
      e["tcp_nodelay"][side] = effective;
      if (!effective.is_boolean())
        issue(e, "insufficient_evidence", side + ": TCP_NODELAY not observed");
      else if (effective != tcp_nodelay)
        issue(e, "failed", side + ": TCP_NODELAY differs from requested policy");
      const auto path = events / (id + "." + side + ".maps");
      const auto endpoint = build / "bin" / side;
      using turtle::submission::MapsState;
      auto expected = libs;
      expected.push_back(observer);
      const auto maps = turtle::submission::process_maps(path, endpoint, expected);
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
    // Task outcome, a valid elapsed interval and controller eligibility are
    // different results. Do not present timings from an unbound attempt.
    const bool measured = e.at("operational") == true &&
                          row.at("prepared_start").at("verified") == true;
    const auto wall = measured ? row.at("benchmark_timing_ns") : Json(nullptr);
    const auto &delta = timing.at("pmu_delta");
    // Validate the values passed through to CSV here, while a malformed
    // result can still be reported as an error on this attempt alone.
    const auto checked_ns = [](const Json &value) {
      if (!value.is_null())
        turtle::artifact::integer(value);
      return value;
    };
    checked_ns(wall);
    if (!wall.is_null() && !delta.is_null()) {
      const auto enabled = turtle::artifact::integer(delta.at("enabled_ns"));
      const auto running = turtle::artifact::integer(delta.at("running_ns"));
      if (enabled == running)
        turtle::artifact::integer(delta.at("cycles"));
    }
    e["controller_wall_ns"] = wall;
    e["wall_status"] = !wall.is_null() ? string("available")
                         : !measured ? string("attempt_or_start_unverified")
                         : timing.value("unavailable_reason", string("boundary_unobserved"));
    if (measured) {
      e["first_greeting_read_ns"] = checked_ns(timing.value("first_greeting_read_ns", Json(nullptr)));
      e["greeting_write_accept_ns"] = checked_ns(timing.value("greeting_write_accept_ns", Json(nullptr)));
    }
    e["sdk_application_interval"] =
        turtle::submission::sdk_application_interval(timing, c.role);
    e["pmu"] = {{"status", row.at("pmu_status").get_ref<const string &>()},
                {"delta", delta},
                {"counter_window", "native_sdk_application_interval"},
                {"clock_for_window", "CLOCK_MONOTONIC"},
                {"cycle_unit", "cpu_cycle"},
                {"begin", timing.at("begin")},
                {"end", timing.at("end")},
                {"controller_qualified", measured && row.at("qualified") == true}};
    try {
      e["application"] = turtle::submission::app_evidence(
          participants, c.scenario, c.auth, summary.at("application"),
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
    const auto root = out / "result";
    const auto summary_path = root / "analysis-summary.json";
    const unsigned wanted = doctor ? 1 : repetitions, warm = doctor ? 0 : warmups;
    Json summary;
    size_t count;
    unsigned expected_successes, expected_qualified;
    try {
      require(fs::is_directory(fs::symlink_status(root)) &&
                  fs::is_regular_file(fs::symlink_status(root / "analysis.json")),
              "controller produced no analysis.json");
      require(fs::is_regular_file(fs::symlink_status(summary_path)),
              "controller produced no valid analysis-summary.json");
      summary = load(summary_path);
      require(summary.at("schema") == "turtle.native-analysis-summary.v1" &&
                  summary.at("run_id").is_string() && summary.at("application").is_object(),
              "invalid controller analysis summary");
      require(summary.at("role") == c.role && summary.at("scenario") == c.scenario &&
                  summary.at("auth") == c.auth && summary.at("warmups") == warm &&
                  summary.at("repetitions") == wanted,
              "controller selected a different role/scenario/auth or attempt schedule");
      const auto n = turtle::artifact::integer(summary.at("attempt_count"));
      const bool collected = summary.at("collection_complete").get<bool>();
      const bool complete = summary.at("complete").get<bool>();
      require(n <= wanted + warm && (collected ? n == wanted + warm : n <= warm) &&
                  (!complete || collected) && (rc == 0) == complete,
              "inconsistent controller analysis status or attempt count");
      if (n == 0) {
        r["reason"] = summary.value("error", string("controller produced no attempts"));
        return r;
      }
      require(!summary.contains("error"), "controller reported a global analysis failure");
      const auto successes = turtle::artifact::integer(summary.at("successful_measurements"));
      const auto qualified = turtle::artifact::integer(summary.at("qualified_samples"));
      require(successes <= (n > warm ? n - warm : 0) && qualified <= successes,
              "invalid controller analysis sample tallies");
      count = n;
      expected_successes = successes;
      expected_qualified = qualified;
    } catch (const std::exception &error) {
      r["state"] = rc == 0 ? "insufficient_evidence" : "failed";
      r["reason"] = error.what();
      return r;
    }

    bool unsupported = false, failure = false, partial = false;
    auto readback_error = [&](const string &message) {
      if (!partial)
        r["reason"] = message;
      partial = true;
    };
    unsigned successes = 0, qualified = 0;
    unsigned operational = 0, verified = 0, verified_connections = 0;
    // Read one finalized row at a time, using the controller's verified
    // schedule rather than resolving paths from an artifact. The aggregate
    // is retained for diagnostics, not parsed by the ordinary CSV path.
    for (size_t index = 0; index < count; ++index) {
      const string name = "attempt-" + std::to_string(index + 1);
      const auto attempt = root / name, path = attempt / "analysis.json";
      try {
        require(fs::is_directory(fs::symlink_status(attempt)) &&
                    fs::is_regular_file(fs::symlink_status(path)),
                "missing or invalid finalized analysis.json");
        const auto row = load(path);
        const bool task_success = row.at("task_success").get<bool>();
        const bool controller_qualified = row.at("qualified").get<bool>();
        require(row.at("qualification").is_string() &&
                    (!controller_qualified || (task_success && row.at("purpose") == "sample")),
                "invalid finalized qualification");
        auto e = connection(row, out, c, summary, index, doctor);
        unsupported |= e.at("state") == "unsupported";
        failure |= e.at("state") == "failed";
        verified_connections += e.at("verified") == true;
        if (row.at("purpose") == "sample") {
          successes += task_success;
          qualified += controller_qualified;
          operational += e.at("operational") == true;
          verified += e.at("verified") == true;
        }
        r["evidence"].push_back(std::move(e));
      } catch (const std::exception &error) {
        readback_error(name + ": " + error.what());
      }
    }
    if (successes > expected_successes || qualified > expected_qualified ||
        (!partial && (successes != expected_successes || qualified != expected_qualified))) {
      r["evidence"] = Json::array();
      r["state"] = rc == 0 ? "insufficient_evidence" : "failed";
      r["reason"] = "finalized rows disagree with controller analysis summary";
      return r;
    }
    const bool controller_ok = rc == 0 && !partial && expected_successes == wanted;
    r["task_successes"] = successes;
    r["qualified_controller_samples"] = doctor ? 0 : qualified;
    r["runtime_verified_samples"] = doctor ? 0 : operational;
    r["verified_connections"] = verified_connections;
    r["verified_samples"] = doctor ? 0 : verified;
    r["ready"] = controller_ok && operational == wanted && !failure;
    r["state"] = controller_ok && verified == wanted && !failure ? "passed"
                 : failure                                    ? "failed"
                 : unsupported && !partial                    ? "unsupported"
                                                              : "insufficient_evidence";
    return r;
  }
};

void csv_row(std::ostream &out, std::initializer_list<string> cells) {
  bool first = true;
  for (const auto &cell : cells) {
    if (!first)
      out.put(',');
    first = false;
    if (cell.find_first_of(",\"\r\n") == string::npos) {
      out << cell;
      continue;
    }
    out.put('"');
    for (char c : cell) {
      out.put(c);
      if (c == '"')
        out.put(c);
    }
    out.put('"');
  }
  out.put('\n');
}

string number_cell(const Json &value) {
  return value.is_null() ? string{} : std::to_string(turtle::artifact::integer(value));
}

string socket_cell(const Json &fact) {
  return fact == true ? "1" : fact == false ? "0" : "";
}

string artifact_path_cell(const fs::path &dir, const Json &value) {
  return value.is_string()
             ? fs::path(value.get_ref<const string &>()).lexically_relative(dir).generic_string()
             : string{};
}

string first_issue(const Json &trial) {
  const auto &issues = trial.at("issues");
  return issues.empty() ? string{} : issues.at(0).at("reason").get<string>();
}

bool performance_qualified(const Json &trial) {
  return trial.at("verified") == true &&
         trial.at("pmu").at("controller_qualified") == true;
}

void write_csv(const fs::path &dir, const Json &result, unsigned repetitions) {
  std::ofstream cases(dir / "cases.csv", std::ios::binary);
  std::ofstream trials(dir / "results.csv", std::ios::binary);
  require(bool(cases) && bool(trials), "could not create CSV results");
  csv_row(cases, {"auth", "scenario", "role", "state", "requested", "verified",
                   "operational", "performance_qualified", "reason", "analysis_path"});
  csv_row(trials, {"auth", "scenario", "role", "purpose", "connection_id",
                    "task_success", "evidence_state", "wall_ns", "wall_status",
                    "first_greeting_read_ns", "cycles", "pmu_status",
                    "performance_qualified", "qualification_reason",
                    "client_tcp_nodelay", "server_tcp_nodelay",
                    "greeting_write_accept_ns", "evidence_reason",
                    "client_stderr", "server_stderr"});
  for (const auto &item : result.at("cases")) {
    const auto auth = item.at("auth").get<string>();
    const auto scenario = item.at("scenario").get<string>();
    const auto role = item.at("role").get<string>();
    const bool ran = item.contains("benchmark");
    const auto &last = item.at(ran ? "benchmark" : "doctor");
    auto reason = last.value("reason", string{});
    unsigned qualified = 0;
    for (const auto &trial : last.at("evidence")) {
      const auto purpose = trial.at("purpose");
      if (reason.empty() && trial.at("state") != "passed" && purpose != "warmup")
        reason = first_issue(trial);
      if (purpose == "sample" && performance_qualified(trial))
        ++qualified;
    }
    if (!ran && reason.empty())
      reason = "doctor did not admit benchmark";
    csv_row(cases, {auth, scenario, role, item.at("state").get<string>(),
                    std::to_string(repetitions),
                    number_cell(last.value("verified_samples", Json(0))),
                    number_cell(last.value("runtime_verified_samples", Json(0))),
                    std::to_string(qualified),
                    reason, artifact_path_cell(dir, last.at("analysis"))});
    for (auto phase : {"doctor", "benchmark"}) {
      if (!item.contains(phase))
        continue;
      for (const auto &trial : item.at(phase).at("evidence")) {
        const auto wall = trial.value("controller_wall_ns", Json(nullptr));
        const auto pmu = trial.value("pmu", Json::object());
        const auto delta = pmu.value("delta", Json(nullptr));
        const bool cycle_count = !wall.is_null() && delta.is_object() &&
                                 delta.at("enabled_ns") == delta.at("running_ns");
        const auto sockets = trial.at("tcp_nodelay");
        const auto errors = trial.value("role_stderr", Json::object());
        csv_row(trials, {auth, scenario, role, trial.at("purpose").get<string>(),
                         trial.at("connection_id").get<string>(),
                         trial.at("task_success") == true ? "true" : "false",
                         trial.at("state").get<string>(), number_cell(wall),
                         trial.value("wall_status", string("attempt_or_start_unverified")),
                         number_cell(trial.value("first_greeting_read_ns", Json(nullptr))),
                         cycle_count ? number_cell(delta.at("cycles")) : string{},
                         wall.is_null() ? "unobserved" : pmu.at("status").get<string>(),
                         performance_qualified(trial) ? "true" : "false",
                         trial.at("controller_qualification").get<string>(),
                         socket_cell(sockets.value("client", Json(nullptr))),
                         socket_cell(sockets.value("server", Json(nullptr))),
                         number_cell(trial.value("greeting_write_accept_ns", Json(nullptr))),
                         first_issue(trial),
                         artifact_path_cell(dir, errors.value("client", Json(nullptr))),
                         artifact_path_cell(dir, errors.value("server", Json(nullptr)))});
      }
    }
  }
  cases.close();
  trials.close();
  require(bool(cases) && bool(trials), "could not save CSV results");
}
} // namespace

int main(int argc, char **argv) {
  try {
    auto &owner = supervisor();
    require(argc == 11, "expected controller run role scenario auth warmups "
                        "repetitions credentials selected-build-directory receipt-checker");
    auto dir = fs::canonical(argv[2]);
    auto build = fs::canonical(argv[9]);
    const auto observer = fs::canonical(build / "runtime/libturtle_observe.so.1");
    require(observer == build / "runtime/libturtle_observe.so.1",
            "staged observer unexpectedly resolves outside its recorded path");
    const auto *requested = std::getenv("TURTLE_TCP_NODELAY");
    const string nodelay = requested ? requested : "";
    require(nodelay.empty() || nodelay == "on" || nodelay == "off",
            "invalid TURTLE_TCP_NODELAY (expected on or off)");
    Job job{fs::canonical(argv[1]), build, observer,
            libraries(build), {}, argv[8], number(argv[6]),
            number(argv[7]), nodelay != "off", {}};
    require(job.repetitions > 0, "repetitions must be positive");
    job.lib_hashes = verify_contents(job.build, job.libs);
    const auto observer_hash = turtle::process::digest(observer);
    job.lib_hashes.emplace(observer.string(), observer_hash);
    Json result = {{"schema", "turtle.submission-run.v2"},
                   {"cases", Json::array()},
                   {"build_directory", build.string()},
                   {"observer_path", observer.string()},
                   {"observer_sha256", observer_hash},
                   {"requested_tcp_nodelay", job.tcp_nodelay},
                   {"target_libraries", Json::array()}};
    std::cout << "TCP_NODELAY: " << (job.tcp_nodelay ? "on" : "off") << '\n';
    for (const auto &lib : job.libs)
      result["target_libraries"].push_back(lib.string());
    bool ok = true, runtime_ok = true;
    for (const auto &auth : choices(argv[5], "both", {"server", "mtls"}))
      for (const auto &scenario :
           choices(argv[4], "all", {"S0", "S1", "S2", "S3", "S4"}))
        for (const auto &role :
             choices(argv[3], "both", {"client", "server"})) {
          owner.check();
          auto out = dir / "runs" / (auth + "-" + scenario + "-" + role);
          require(!fs::exists(out),
                  "case output already exists: " + out.string());
          Json item = {{"auth", auth}, {"scenario", scenario}, {"role", role}};
          const Case selection{role, scenario, auth};
          item["doctor"] = job.phase(out / "doctor", selection, true);
          owner.check();
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
    auto final_hashes = verify_contents(job.build, job.libs);
    final_hashes.emplace(observer.string(), turtle::process::digest(observer));
    require(final_hashes == job.lib_hashes,
            "private library or observer digest records changed during the job");
    const int receipt_exit = owner.run({"/bin/sh", argv[10], "verify", build.string()});
    if (receipt_exit)
      return receipt_exit;
    result["library_hash_check"] = "matched_before_and_after_run";
    result["runtime_complete"] = runtime_ok;
    result["complete"] = ok;
    save(dir / "summary.json", result);
    write_csv(dir, result, job.repetitions);
    std::cout << "Cases: " << dir / "cases.csv" << '\n'
              << "Trials: " << dir / "results.csv" << '\n';
    return ok ? 0 : 1;
  } catch (const Interrupted &e) {
    std::cerr << "submission job: interrupted\n";
    return 128 + e.signal;
  } catch (const std::exception &e) {
    std::cerr << "submission job: " << e.what() << '\n';
    return 1;
  }
}
