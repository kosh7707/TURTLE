#include "analysis/analysis.hpp"
#include "analysis/evidence.hpp"
#include "profiling/profiling.hpp"
#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <stdexcept>

namespace turtle::analysis {
namespace fs = std::filesystem;
using namespace evidence;
using artifact::integer;
using artifact::measurement;
namespace {
bool has(const Json &list, const std::string &value) {
  return std::find(list.begin(), list.end(), value) != list.end();
}
Json elapsed(const Json &a, const Json &b, const std::string &clock) {
  if (!a.contains(clock) || !b.contains(clock) || a.at(clock).is_null() ||
      b.at(clock).is_null())
    return missing("clock_unavailable");
  const auto x = integer(a.at(clock)), y = integer(b.at(clock));
  return y < x ? missing("clock_reversed") : measurement(y - x);
}
void check_outcome(const Json &s, const Json &a, const Task &t,
                   const std::string &role) {
  require(s.at("schema") == "turtle.endpoint.v4" &&
              s.at("run_id") == a.at("run_id") &&
              s.at("purpose") == a.at("purpose") && s.at("role") == role &&
              s.at("measured_role") == t.role && s.at("auth") == t.auth &&
              s.at("scenario").at("name") == t.name,
          "endpoint_identity_or_task_mismatch");
  const auto &sc = s.at("scenario"), &n = s.at("negotiated");
  if (s.at("status") != "ok" || sc.at("complete") != true)
    throw std::runtime_error("endpoint_failed:" +
                             s.value("invalid_reason", Json(nullptr)).dump());
  require(n.at("version") == 0x0304 && n.at("resumed") == false,
          "not_full_tls13");
  require(n.at("profile") == (t.auth == "mtls" ? 2 : 1),
          "authentication_policy_mismatch");
  bool must_verify = role == "client" || t.auth == "mtls";
  require(n.at("peer_verified") == must_verify,
          "authentication_evidence_mismatch");
  require(sc.at("content_verified") == true &&
              integer(sc.at("plaintext_sent")) == t.sent(role == "client") &&
              integer(sc.at("plaintext_received")) == t.sent(role != "client"),
          "plaintext_contract_mismatch");
}
Json read_events(const fs::path &dir, const Json &s) {
  Json events = Json::array();
  std::istringstream input(artifact::read_text(dir / "events.jsonl"));
  for (std::string line; std::getline(input, line);) {
    auto e = Json::parse(line);
    require(e.at("schema") == "turtle.event.v2" &&
                e.at("id") == events.size() + 1 &&
                e.at("run_id") == s.at("run_id") &&
                e.at("connection_id") == s.at("connection_id") &&
                e.at("role") == s.at("role"),
            "event_identity_or_sequence_mismatch");
    auto parent = integer(e.at("parent"));
    require(parent <= events.size(), "event_parent_missing");
    if (parent) {
      const auto &p = events.at(parent - 1);
      require(p.at("kind") == "call" || p.at("kind") == "transport",
              "invalid_event_parent");
    }
    events.push_back(std::move(e));
  }
  return events;
}
void timing(const Task &task, Endpoint &ep) {
  const auto &scenario = ep.summary.at("scenario");
  const bool client = task.role == "client";
  Json start = nullptr, stop = nullptr, handshake_end = nullptr,
       verified = nullptr;
  std::uint64_t sent = 0, received = 0;
  std::map<std::string, Json> edges;
  for (const auto &e : ep.events) {
    if (e.at("kind") != "call")
      continue;
    require(available(elapsed(e.at("begin"), e.at("end"), "wall_ns")),
            "invalid_call_wall_clock");
    const auto &op = e.at("operation");
    if (start.is_null() && (op == "server_first" || op == "handshake"))
      start = e;
    if (!e.at("success").get<bool>())
      continue;
    if (op == "handshake") {
      handshake_end = e;
      if (task.name == "S0")
        stop = e;
    } else if (op == "content_verify") {
      verified = e;
      const auto b = integer(e.at("plaintext_end")),
                 a = integer(e.at("plaintext_begin"));
      require(b == received && a < b, "verification_range_mismatch");
      if (!client) {
        require(a == 0 && b == task.request,
                "request_verification_range_mismatch");
        edges["request_verified"] = e;
        if (task.name == "S1")
          stop = e;
      } else if (task.greeting && a == 0 && b == task.greeting)
        edges["greeting_verified"] = e;
      else if (task.response && a == task.greeting && b == task.sent(false))
        edges["response_verified"] = e;
      else
        throw std::runtime_error("response_verification_range_mismatch");
    } else if (op == "application_read" || op == "application_write" ||
               op == "server_first") {
      bool read = op == "application_read";
      auto &offset = read ? received : sent;
      auto b = integer(e.at("plaintext_end")),
           a = integer(e.at("plaintext_begin"));
      require(offset == a && b > a && b - a == integer(e.at("transferred")),
              "plaintext_call_range_mismatch");
      offset = b;
      if (!client && task.response && op == "application_write")
        require(!verified.is_null() && received == task.request &&
                    !handshake_end.is_null(),
                "response_before_request_validation");
      if (client && read && task.name != "S0") {
        if (task.greeting && a == 0)
          edges["first_greeting"] = e;
        if (task.response && a <= task.greeting && task.greeting < b)
          edges["first_response"] = e;
        auto target = task.name == "S4" ? task.greeting : 0u;
        if (a <= target && target < b && stop.is_null())
          stop = e;
      } else if ((task.name == "S1" && client && !read && b == task.request) ||
                 (!client && !read && b == task.sent(false)))
        stop = e;
    }
  }
  if (task.recording != "off") {
    require(!start.is_null() && !handshake_end.is_null() && !stop.is_null(),
            "required_call_boundary_missing");
    require(
        (client || !task.request || edges.contains("request_verified")) &&
            (!client || !task.greeting ||
             edges.contains("greeting_verified")) &&
            (!client || !task.response || edges.contains("response_verified")),
        "content_validation_event_missing");
    require(sent == task.sent(client) && received == task.sent(!client),
            "plaintext_call_trace_incomplete");
    require(start.at("id") == scenario.at("begin_event") &&
                stop.at("id") == scenario.at("end_event") &&
                start.at("begin") == scenario.at("begin") &&
                stop.at("end") == scenario.at("end"),
            "scenario_boundary_disagrees_with_calls");
  }
  const auto &begin =
      task.recording == "off" ? scenario.at("begin") : start.at("begin");
  const auto &end =
      task.recording == "off" ? scenario.at("end") : stop.at("end");
  for (const char *clock : clocks) {
    for (const auto &[name, e] : edges) {
      auto m = elapsed(begin, e.at("end"), clock);
      m.update({{"begin_event", start.at("id")}, {"end_event", e.at("id")}});
      ep.metrics[name + "_" + clock] = m;
    }
    ep.metrics[std::string("scenario_") + clock] = elapsed(begin, end, clock);
    if (!handshake_end.is_null())
      ep.metrics[std::string("handshake_") + clock] =
          elapsed(begin, handshake_end.at("end"), clock);
    if (!verified.is_null())
      ep.metrics[std::string("content_verified_") + clock] =
          elapsed(begin, verified.at("end"), clock);
  }
}

Json measurement_rows(const Json &role_report, const std::string &role,
                      const std::string &purpose, bool eligible,
                      bool ordinary) {
  Json rows = Json::array();
  auto append = [&](const std::string &name, Json metric, const char *group,
                    const std::string &scope, bool sample) {
    const bool valid = eligible && sample && available(metric);
    Json exclusion = nullptr;
    if (!valid) {
      if (!eligible)
        exclusion = "ineligible_attempt";
      else if (purpose != "measurement")
        exclusion = purpose;
      else if (!sample)
        exclusion = "separate_perf_collection";
      else
        exclusion = metric.at("reason");
    }
    const char *unit = "count";
    if (name.ends_with("_ns"))
      unit = "ns";
    else if (name.ends_with("bytes"))
      unit = "bytes";
    metric.update({{"metric", name},
                   {"role", role},
                   {"group", group},
                   {"scope", scope},
                   {"unit", unit},
                   {"valid_sample", valid},
                   {"excluded_reason", std::move(exclusion)}});
    rows.push_back(std::move(metric));
  };

  for (const auto &[name, metric] : role_report.at("metrics").items())
    append(name, metric, "metrics", "", ordinary);
  const auto operations =
      role_report.at("counters").value("operations", Json::object());
  for (const auto &[scope, metrics] : operations.items()) {
    if (metrics.empty())
      continue;
    const bool sample = purpose == "measurement" &&
                        available(metrics.at("cycles")) &&
                        available(metrics.at("instructions"));
    for (const auto &[name, metric] : metrics.items())
      append(name, metric, "counter_metrics", scope, sample);
  }
  return rows;
}
} // namespace
Json assess(const fs::path &dir, const Json &config, const Json &scheduled) {
  Task t(config);
  const auto purpose = scheduled.at("purpose").get<std::string>();
  const bool probe = purpose == "capability", profile = purpose == "profile";
  const auto required = config.value("required_metrics", Json::array());
  Json task_errors = Json::array(), membership = Json::array(),
       metric_errors = Json::array();
  Json roles = Json::object(), observations = Json::object(),
       out = Json::object();
  Endpoint ep;
  ep.phases = ep.metrics = ep.records = ep.links = Json::object();
  ep.events = Json::array();
  Json counters_report = {{"requested", false}}, cpu = {{"requested", false}};
  observations["socket_only"] = {
      {"retransmissions", "unobservable"},
      {"cross_direction_tcp_arrival", "indeterminate"}};
  for (auto k : {"records", "public_io", "headers", "capture", "perf_counters",
                 "cpu_samples"})
    observations[k] = measurement(nullptr, "not_collected", "not_observed");
  try {
    auto processes = artifact::load(dir / "processes.json");
    require(processes.at("run_id") == scheduled.at("run_id"),
            "process_run_identity_mismatch");
    if (!processes.at("error").is_null())
      task_errors.push_back(processes.at("error"));
    for (auto role : {"client", "server"})
      if (processes.at("returncodes").at(role) != 0)
        task_errors.push_back(std::string(role) + ":nonzero_exit");
  } catch (const std::exception &e) {
    task_errors.push_back(e.what());
  }
  if (!scheduled.value("error", Json(nullptr)).is_null())
    task_errors.push_back(scheduled.at("error"));
  for (auto role : {"client", "server"}) {
    try {
      auto s = artifact::load(dir / role / "endpoint.json");
      if (role == t.role)
        ep.summary = s;
      roles[role] = {{"negotiated", s.at("negotiated")},
                     {"scenario", s.at("scenario")},
                     {"shutdown", s.at("shutdown")},
                     {"implementation", s.at("implementation")}};
      if (s.contains("capability"))
        roles[role]["capability"] = s.at("capability");
      check_outcome(s, scheduled, t, role);
    } catch (const std::exception &e) {
      task_errors.push_back(std::string(role) + ":" + e.what());
    }
  }
  if (probe) {
    try {
      const auto &c = roles.at("client").at("capability"),
                 &s = roles.at("server").at("capability");
      const auto client_log =
          artifact::read_text(dir / "client" / "control.log");
      const auto server_log =
          artifact::read_text(dir / "server" / "control.log");
      const auto presend =
          "PRESEND " + std::to_string(integer(s.at("server_submitted"))) + "\n";
      require(client_log == "READY\nPAUSED\nGREETING\n" &&
                  server_log.starts_with("LISTEN ") &&
                  server_log.ends_with("\nREADY\n" + presend),
              "presend_greeting_not_validated_while_server_paused");
      require(t.greeting && c.at("client_paused") == true &&
                  s.at("server_presend") == true &&
                  integer(s.at("server_submitted")) > 0 &&
                  c.at("server_submitted") == s.at("server_submitted") &&
                  integer(c.at("queued_before_resume")) >=
                      integer(s.at("server_submitted")),
              "presend_probe_not_demonstrated");
    } catch (const std::exception &e) {
      task_errors.push_back(e.what());
    }
  }
  try {
    const auto expected = config.value("expected", Json::object());
    const auto peer = t.role == "client" ? "server" : "client";
    const auto other = artifact::load(dir / peer / "endpoint.json");
    require(other.at("streams").empty() &&
                !fs::exists(dir / peer / "events.jsonl") &&
                !other.at("collection").value("cpu_samples", false) &&
                !other.at("collection").value("perf_counters", false),
            "peer_was_instrumented");
    require(other.at("connection_id") == ep.summary.at("connection_id"),
            "peer_connection_identity_mismatch");
    for (auto k : {"cipher", "group"}) {
      auto get = [&](const char *role) {
        const auto &prop = roles.at(role).at("negotiated").at(k);
        require(available(prop) && prop.at("value").is_string(),
                "negotiation_not_observed");
        return canonical(prop.at("value"));
      };
      auto actual = get("client");
      require(!actual.empty() && actual == get("server"),
              "peer_negotiation_mismatch");
      require(!expected.contains(k) || actual == canonical(expected.at(k)),
              "requested_negotiation_mismatch");
    }
    require(ep.summary.at("recording") == t.recording &&
                ep.summary.at("collection").at("framing") == "none",
            "measurement_path_mismatch");
  } catch (const std::exception &e) {
    membership.push_back(e.what());
  }
  const auto measured = dir / t.role;
  if (!probe) {
    try {
      if (t.recording != "off")
        ep.events = read_events(measured, ep.summary);
      timing(t, ep);
    } catch (const std::exception &e) {
      ep.metrics["scenario_wall_ns"] = missing(e.what());
    }
    observations["scenario_wall_ns"] = ep.metrics.value(
        "scenario_wall_ns", missing("required_call_boundary_missing"));
  }
  if (!probe)
    evidence::collect(
        dir, t,
        has(required, "capture") ||
            has(config.value("optional_metrics", Json::array()), "capture"),
        task_errors.empty() && membership.empty(), ep, roles, observations,
        out);
  try {
    if (ep.summary.at("collection").value("perf_counters", false)) {
      counters_report = counters(measured, ep);
      auto scope =
          counters_report.at("operations").value("scenario", Json::object());
      bool good = scope.contains("cycles") && available(scope.at("cycles")) &&
                  available(scope.at("instructions"));
      observations["perf_counters"] =
          good ? measurement(true)
               : missing(
                     counters_report.value("reason", Json(nullptr)).is_string()
                         ? counters_report.at("reason").get<std::string>()
                         : "scenario_counters_unavailable");
    }
    if (profile) {
      cpu = profiling::analyze(measured, ep.summary, ep.events, ep.phases);
      const auto window = cpu.value("scenario", Json::object());
      bool named = window.value("sample_count", 0u) >
                   window.value("unknown_symbol_samples", 0u);
      observations["cpu_samples"] =
          cpu.value("availability", "") == "available" && named
              ? measurement(true)
              : missing(cpu.value("reason", Json(nullptr)).is_string()
                            ? cpu.at("reason").get<std::string>()
                            : "no_named_scenario_samples");
    }
  } catch (const std::exception &e) {
    observations[profile ? "cpu_samples" : "perf_counters"] = missing(e.what());
  }
  const auto unavailable =
      scheduled.value("unavailable_metrics", Json::object());
  for (const auto &[key, why] : unavailable.items())
    if (observations.contains(key) && !available(observations.at(key)))
      observations[key] = measurement(nullptr, "unsupported", why);
  for (const auto &k : required) {
    if (probe || (k == "cpu_samples" && !profile) ||
        (k == "perf_counters" && profile))
      continue;
    auto m =
        observations.value(k.get<std::string>(), missing("metric_unknown"));
    if (!available(m))
      metric_errors.push_back(k.get<std::string>() + ":" +
                              m.at("reason").dump());
  }
  if (!probe && !available(observations.at("scenario_wall_ns")) &&
      !has(required, "scenario_wall_ns"))
    metric_errors.push_back("scenario_wall_ns:required_boundary_unavailable");
  bool success = task_errors.empty(),
       eligible = success && membership.empty() && metric_errors.empty();
  bool ordinary =
      purpose == "measurement" && !counters_report.value("requested", false);
  auto &role = roles[t.role];
  role.update({{"metrics", ep.metrics},
               {"records", ep.records},
               {"event_links", ep.links},
               {"cpu_profile", cpu},
               {"counters", counters_report}});
  auto rows = measurement_rows(role, t.role, purpose, eligible, ordinary);
  Json reasons = task_errors;
  for (const auto &m : {membership, metric_errors})
    for (const auto &r : m)
      reasons.push_back(r);
  out.update(
      {{"schema", "turtle.attempt-report.v4"},
       {"run_id", scheduled.at("run_id")},
       {"purpose", purpose},
       {"success", success},
       {"configuration_matches", membership.empty()},
       {"required_metrics_valid", metric_errors.empty()},
       {"eligible", eligible},
       {"ordinary_timing_sample", ordinary},
       {"invalid_reasons", reasons},
       {"task_invalid_reasons", task_errors},
       {"configuration_invalid_reasons", membership},
       {"required_metric_invalid_reasons", metric_errors},
       {"observations", observations},
       {"roles", roles},
       {"phase_complete", false},
       {"phase_invalid_reasons", Json::array({"legacy_phase_model_not_used"})},
       {"network_complete", available(observations.at("capture"))},
       {"network_invalid_reasons", Json::array()},
       {"perf_complete",
        (!counters_report.value("requested", false) ||
         available(observations.at("perf_counters"))) &&
            (!profile || available(observations.at("cpu_samples")))},
       {"perf_invalid_reasons", Json::array()},
       {"measurements", rows}});
  artifact::save(dir / "analysis.json", out);
  return out;
}

bool regenerate_lifecycle(const fs::path &root, const Json &manifest) {
  const auto &spec = manifest.at("spec");
  std::map<std::string, Json> configs;
  for (const auto &c : spec.at("configurations"))
    require(configs.emplace(c.at("id"), c).second, "duplicate_configuration");
  bool valid = manifest.at("status") == "complete" &&
               manifest.value("blocked", Json::object()).empty();
  Json diagnostics = Json::array(), attempts = Json::array();
  std::set<std::string> ids, dirs;
  using Slot = std::tuple<std::string, std::string, std::uint64_t>;
  auto slot = [](const Json &a) -> Slot {
    return {a.at("configuration"), a.at("purpose"),
            integer(a.value("repeat", Json(0)))};
  };
  std::set<Slot> planned, seen;
  for (const auto &a : manifest.at("order")) {
    auto [id, purpose, repeat] = slot(a);
    auto &cfg = configs.at(id);
    bool probe = cfg.at("scenario") == "S2" || cfg.at("scenario") == "S4";
    require((purpose == "measurement" &&
             repeat < integer(spec.at("repetitions"))) ||
                (purpose == "warmup" && repeat < integer(cfg.at("warmups"))) ||
                (purpose == "capability" && probe && repeat == 0) ||
                (purpose == "profile" && repeat == 0 &&
                 (has(cfg.at("required_metrics"), "cpu_samples") ||
                  has(cfg.value("optional_metrics", Json::array()),
                      "cpu_samples"))),
            "unexpected_schedule_slot");
    require(configs.contains(a.at("configuration")) &&
                planned.insert(slot(a)).second,
            "unknown_configuration_or_duplicate_schedule_slot");
  }
  std::map<std::string, std::size_t> samples, warmed;
  std::set<std::string> proven, profiled;
  std::size_t position = 0;
  const auto canonical_root = fs::canonical(root);
  std::size_t successes = 0, eligible = 0;
  for (const auto &a : manifest.at("attempts")) {
    auto id = a.at("configuration").get<std::string>();
    auto d = a.at("directory").get<std::string>();
    require(planned.contains(slot(a)) && seen.insert(slot(a)).second &&
                ids.insert(a.at("run_id")).second && dirs.insert(d).second,
            "duplicate_or_unscheduled_attempt");
    auto planned_pos = std::find_if(
        manifest.at("order").begin() + position, manifest.at("order").end(),
        [&](const auto &s) { return slot(s) == slot(a); });
    require(planned_pos != manifest.at("order").end(),
            "attempt_schedule_out_of_order");
    position = planned_pos - manifest.at("order").begin() + 1;
    auto &cfg = configs.at(id);
    const fs::path declared(d);
    const auto relative =
        fs::canonical(root / declared).lexically_relative(canonical_root);
    // Each slot is a direct child of the actual attempts directory. Reject
    // absolute paths, dot segments, aliases and outward-pointing symlinks.
    require(declared.parent_path() == "attempts" &&
                !declared.filename().empty() && declared.filename() != "." &&
                declared.filename() != ".." && relative == declared,
            "attempt_directory_outside_run");
    auto r = assess(root / d, cfg, a);
    bool needs_probe = cfg.at("scenario") == "S2" || cfg.at("scenario") == "S4";
    bool gate = (!needs_probe || proven.contains(id) ||
                 a.at("purpose") == "capability") &&
                (a.at("purpose") != "measurement" ||
                 (warmed[id] == integer(cfg.at("warmups")) &&
                  (!has(cfg.at("required_metrics"), "cpu_samples") ||
                   profiled.contains(id))));
    if (!gate) {
      r["eligible"] = false;
      r["invalid_reasons"].push_back("prerequisite_attempt_not_verified");
      for (auto &row : r.at("measurements")) {
        row["valid_sample"] = false;
        row["excluded_reason"] = "prerequisite_attempt_not_verified";
      }
      artifact::save(root / d / "analysis.json", r);
    }
    if (r.at("eligible") == true) {
      if (a.at("purpose") == "warmup")
        ++warmed[id];
      if (a.at("purpose") == "capability")
        proven.insert(id);
      if (a.at("purpose") == "profile" &&
          available(r.at("observations").at("cpu_samples")))
        profiled.insert(id);
    }
    Json row = {{"directory", d},
                {"run_id", a.at("run_id")},
                {"configuration", id},
                {"purpose", a.at("purpose")},
                {"complete", r.at("eligible")},
                {"success", r.at("success")},
                {"invalid_reasons", r.at("invalid_reasons")}};
    bool optional_profile =
        a.at("purpose") == "profile" &&
        !has(configs.at(id).at("required_metrics"), "cpu_samples");
    valid = valid && (r.at("eligible") == true || optional_profile);
    if (a.at("purpose") == "measurement") {
      attempts.push_back(row);
      ++samples[id];
      successes += r.at("success") == true;
      eligible += r.at("eligible") == true;
    } else
      diagnostics.push_back(row);
  }
  valid = valid && seen == planned;
  for (const auto &[id, config] : configs)
    valid = valid && samples[id] == integer(spec.at("repetitions")) &&
            warmed[id] == integer(config.at("warmups"));
  artifact::save(root / "analysis.json",
                 {{"schema", "turtle.run-analysis.v2"},
                  {"complete", valid},
                  {"measurement_count", attempts.size()},
                  {"successful_measurements", successes},
                  {"eligible_measurements", eligible},
                  {"attempts", attempts},
                  {"diagnostics", diagnostics}});
  return valid;
}
} // namespace turtle::analysis
