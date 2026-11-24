#include "analysis/analysis.hpp"
#include "capture/capture.hpp"
#include "profiling/profiling.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
namespace turtle::analysis {
using artifact::integer;
using artifact::measurement;
namespace {
std::vector<std::string> metrics() {
  std::vector<std::string> r;
  for (auto op :
       {"prepare", "handshake", "scenario", "first_use", "frame", "socket",
        "handshake_outside_transport", "handshake_before_shared_send_gap"})
    for (auto clock : clocks)
      r.emplace_back(std::string(op) + "_" + clock);
  for (auto layer : {"tls", "wire"})
    for (auto direction : {"send", "receive"})
      r.emplace_back(std::string(layer) + "_" + direction + "_bytes");
  for (auto n : {"retransmitted_send_bytes", "tcp_send_payload_bytes",
                 "captured_send_link_bytes"})
    r.emplace_back(n);
  return r;
}
std::vector<std::string> phase_metrics() {
  std::vector<std::string> r;
  for (auto kind :
       {"interval", "interval_socket", "io_span", "socket", "exclusive_frame"})
    for (auto k : clocks)
      r.emplace_back(std::string(kind) + "_" + k);
  for (auto n : {"tls_bytes", "wire_bytes", "frame_bytes", "record_count",
                 "tcp_payload_bytes", "retransmitted_bytes"})
    r.emplace_back(n);
  return r;
}
std::string unit(const std::string &name) {
  if (name.ends_with("_ns"))
    return "ns";
  if (name.ends_with("bytes"))
    return "bytes";
  if (name.starts_with("cycles"))
    return "cycles";
  if (name.starts_with("instructions"))
    return "instructions";
  return "count";
}
void measurements(Json &result) {
  Json rows = Json::array();
  bool success = result.at("success"),
       ordinary = result.at("ordinary_timing_sample"),
       phase_complete = result.at("phase_complete");
  auto row = [&](const std::string &role, const std::string &group,
                 const std::string &scope, const std::string &name, Json m,
                 bool eligible, const std::string &exclusion) {
    bool valid = success && eligible && m.at("availability") == "available" &&
                 !m.at("value").is_null();
    m["unit"] = unit(name);
    m["valid_sample"] = valid;
    m["excluded_reason"] = valid                      ? Json(nullptr)
                           : !success                 ? Json("failed_attempt")
                           : !eligible                ? Json(exclusion)
                           : m.at("reason").is_null() ? m.at("availability")
                                                      : m.at("reason");
    m.update(
        {{"role", role}, {"group", group}, {"scope", scope}, {"metric", name}});
    rows.push_back(m);
  };
  for (auto role : {"client", "server"}) {
    auto data = result.at("roles").value(role, Json::object());
    for (const auto &name : metrics())
      row(role, "metrics", "", name,
          data.value("metrics", Json::object())
              .value(name, measurement(nullptr, "missing",
                                       "endpoint_metric_missing")),
          ordinary, "separate_perf_collection");
    for (auto phase : phase_names) {
      Json m = Json::object();
      for (const auto &p :
           data.value("phases", Json::object()).value("rows", Json::array()))
        if (p.at("phase") == phase)
          m = p.at("metrics");
      for (const auto &name : phase_metrics())
        row(role, "phase_metrics", phase, name,
            m.value(name, measurement(nullptr, "missing",
                                      "phase_analysis_incomplete")),
            ordinary && phase_complete,
            !ordinary ? "separate_perf_collection" : "phase_incomplete");
    }
    auto counters = data.value("counters", Json::object());
    if (counters.value("requested",
                       result.value("perf_counters_requested", false)))
      for (auto scope :
           {"prepare", "handshake", "scenario", "first_use", "client_hello",
            "server_hello", "server_auth", "client_finished"}) {
        bool phase = std::find(phase_names.begin(), phase_names.end(),
                               std::string(scope)) != phase_names.end();
        auto m = counters.value(phase ? "phases" : "operations", Json::object())
                     .value(scope, Json::object());
        for (auto name :
             {"cycles", "instructions", "cycles_raw", "instructions_raw",
              "time_enabled_ns", "time_running_ns"})
          row(role, "counter_metrics", scope, name,
              m.value(name,
                      measurement(nullptr,
                                  counters.value("availability",
                                                 std::string("missing")),
                                  counters.value("reason", Json(nullptr)))),
              !phase || phase_complete, "phase_incomplete");
      }
  }
  result["measurements"] = rows;
}
} // namespace
Json attempt(const std::filesystem::path &root, Json error) {
  Endpoints eps;
  Json reasons = Json::array();
  auto process = std::filesystem::exists(root / "processes.json")
                     ? artifact::load(root / "processes.json")
                     : Json::object();
  if (!error.is_null())
    reasons.push_back(error);
  else if (!process.value("error", Json(nullptr)).is_null())
    reasons.push_back(process.at("error"));
  for (auto role : {"client", "server"})
    try {
      auto ep = endpoint(root / role);
      if (ep.summary.at("role") != role)
        throw std::runtime_error("endpoint_role_mismatch");
      if (ep.summary.at("status") != "ok")
        reasons.push_back(std::string(role) + ":" +
                          ep.summary.at("invalid_reason").dump());
      eps.emplace(role, std::move(ep));
    } catch (const std::exception &e) {
      reasons.push_back(std::string(role) + ":" + e.what());
    }
  if (eps.size() == 2) {
    if (eps.at("client").summary.at("run_id") !=
        eps.at("server").summary.at("run_id"))
      reasons.push_back("peer_run_identity_mismatch");
    for (auto sender : {"client", "server"}) {
      auto receiver = std::string(sender) == "client" ? "server" : "client";
      const auto &a = eps.at(sender);
      const auto &b = eps.at(receiver);
      auto sent = integer(a.summary.at("scenario").at("wire_send_bytes")),
           received =
               integer(b.summary.at("scenario").at("wire_receive_bytes"));
      if (sent != received || sent > a.streams.at("send").size() ||
          received > b.streams.at("receive").size() ||
          !std::equal(a.streams.at("send").begin(),
                      a.streams.at("send").begin() +
                          static_cast<std::ptrdiff_t>(std::min<std::uint64_t>(
                              sent, a.streams.at("send").size())),
                      b.streams.at("receive").begin()))
        reasons.push_back(std::string(sender) +
                          "_scenario_stream_peer_mismatch");
    }
  }
  Json network = std::filesystem::exists(root / "network.json")
                     ? artifact::load(root / "network.json")
                     : Json{{"availability", "missing"}},
       observations = Json::object();
  if (eps.size() == 2 && network.value("availability", "") == "available") {
    std::map<std::string, Bytes> streams{
        {"client_to_server", eps.at("client").streams.at("send")},
        {"server_to_client", eps.at("server").streams.at("send")}};
    std::map<std::string, std::uint64_t> required{
        {"client_to_server",
         integer(
             eps.at("client").summary.at("scenario").at("wire_send_bytes"))},
        {"server_to_client",
         integer(
             eps.at("server").summary.at("scenario").at("wire_send_bytes"))}};
    for (auto role : {"client", "server"})
      try {
        auto observed =
            capture::analyze(root / (std::string(role) + ".pcap"), streams,
                             required, "192.0.2.2", "198.51.100.2");
        observations[role] = observed;
        auto direction = flow(role, "send");
        const auto &out = observed.at(direction);
        bool healthy = out.at("availability") == "available" &&
                       network.value("capture", Json::object())
                               .value(role, Json::object())
                               .value("availability", "") == "available";
        auto end = required.at(direction);
        std::uint64_t repeated = 0, payload = 0;
        for (const auto &p : out.at("packets")) {
          if (integer(p.at("payload_bytes"))) {
            auto a = integer(p.at("wire_begin")),
                 b = std::min(integer(p.at("wire_end")), end);
            if (b > a)
              payload += b - a;
          }
          for (const auto &r : p.at("retransmitted_ranges")) {
            auto a = integer(r.at(0)), b = std::min(integer(r.at(1)), end);
            if (b > a)
              repeated += b - a;
          }
        }
        for (const auto &[name, n] : std::map<std::string, std::uint64_t>{
                 {"retransmitted_send_bytes", repeated},
                 {"tcp_send_payload_bytes", payload},
                 {"captured_send_link_bytes", integer(out.at("link_bytes"))}})
          eps.at(role).metrics[name] =
              measurement(healthy ? Json(n) : Json(nullptr),
                          healthy ? "available" : "missing",
                          healthy ? Json(nullptr) : Json("capture_incomplete"));
      } catch (const std::exception &e) {
        observations[role] = {{"availability", "missing"},
                              {"reason", e.what()}};
        for (auto name : {"retransmitted_send_bytes", "tcp_send_payload_bytes",
                          "captured_send_link_bytes"})
          eps.at(role).metrics[name] =
              measurement(nullptr, "missing", e.what());
      }
  }
  Json drops = Json::object(), network_reasons = Json::array();
  bool collected = network.value("availability", "") != "not_collected";
  for (const auto &[direction, interface] : std::map<std::string, std::string>{
           {"client_to_server", "ms"}, {"server_to_client", "mc"}}) {
    Json before = nullptr, after = nullptr;
    for (auto stage : {"before", "after"})
      for (const auto &q : network.value(stage, Json::object())
                               .value("middle", Json::object())
                               .value("qdisc", Json::array()))
        if (q.value("dev", "") == interface && q.value("kind", "") == "netem")
          (std::string(stage) == "before" ? before : after) = q;
    if (!before.is_null() && !after.is_null() && before.contains("drops") &&
        after.contains("drops") &&
        integer(after.at("drops")) >= integer(before.at("drops")))
      drops[direction] =
          measurement(integer(after.at("drops")) - integer(before.at("drops")));
    else
      drops[direction] =
          measurement(nullptr, collected ? "missing" : "not_collected");
  }
  if (collected) {
    if (network.value("availability", "") != "available")
      network_reasons.push_back("network_setup_incomplete");
    for (auto stage : {"before", "after"})
      for (auto role : {"client", "middle", "server"}) {
        auto state =
            network.value(stage, Json::object()).value(role, Json::object());
        bool have = !state.value("links", Json::array()).empty() &&
                    !state.value("qdisc", Json::array()).empty();
        for (const auto &iface : std::string(role) == "middle"
                                     ? std::vector<std::string>{"mc", "ms"}
                                     : std::vector<std::string>{"eth0"})
          have = have &&
                 state.value("offload", Json::object()).contains(iface) &&
                 !state.at("offload").at(iface).get<std::string>().empty();
        if (!have)
          network_reasons.push_back(std::string(stage) + "_" + role +
                                    "_state_missing");
      }
    if (network.contains("snapshot_error"))
      network_reasons.push_back("network_snapshot_failed");
    for (const auto &[name, m] : drops.items())
      if (m.at("availability") != "available")
        network_reasons.push_back(name + "_qdisc_statistics_missing");
    for (auto role : {"client", "server"}) {
      bool have = network.value("capture", Json::object())
                      .value(role, Json::object())
                      .value("availability", "") == "available";
      for (auto direction : {"client_to_server", "server_to_client"})
        have = have && observations.value(role, Json::object())
                               .value(direction, Json::object())
                               .value("availability", "") == "available";
      if (!have)
        network_reasons.push_back(std::string(role) + "_capture_incomplete");
    }
    if (!network.contains("cleanup_errors"))
      network_reasons.push_back("network_cleanup_status_missing");
    else if (!network.at("cleanup_errors").empty())
      network_reasons.push_back("network_cleanup_failed");
  }
  bool success = reasons.empty() && eps.size() == 2;
  auto phase = phases(eps, observations, network, success);
  auto requested = process.value("measurement", Json::object());
  bool perf_counters = requested.value("perf_counters", false),
       cpu_samples = requested.contains("cpu_samples"),
       perf_requested = perf_counters || cpu_samples;
  Json perf_reasons = Json::array(), roles = Json::object();
  if (perf_requested && eps.size() != 2)
    perf_reasons.push_back("perf_requested_but_endpoint_data_missing");
  for (auto &[role, ep] : eps) {
    auto c = counters(root / role, ep),
         p = profiling::analyze(root / role, ep.summary, ep.events, ep.phases);
    if (c.at("requested") == true && c.at("complete") != true)
      perf_reasons.push_back(role + ":counter_scope_incomplete");
    if (p.at("requested") == true && p.at("availability") != "available")
      perf_reasons.push_back(role + ":cpu_profile_incomplete");
    bool ordinary =
        !ep.summary.at("collection").value("perf_counters", false) &&
        !ep.summary.at("collection").value("cpu_samples", false);
    perf_requested = perf_requested || !ordinary;
    for (auto clock : clocks)
      for (const auto &[name, key] : std::map<std::string, std::string>{
               {"handshake_outside_transport", "outside_transport_sum"},
               {"handshake_before_shared_send_gap",
                "before_shared_send_gap_sum"}}) {
        Json value = ep.phases.value("accounting", Json::object())
                         .value(clock, Json::object())
                         .value(key, Json(nullptr));
        ep.metrics[name + "_" + clock] = measurement(
            value, phase.at("complete") == true ? "available" : "missing",
            phase.at("complete") == true ? Json(nullptr)
                                         : Json("phase_analysis_incomplete"));
      }
    roles[role] = {{"metrics", ep.metrics},
                   {"records", ep.records},
                   {"shutdown", ep.summary.at("shutdown")},
                   {"event_links", ep.links},
                   {"phases", ep.phases},
                   {"counters", c},
                   {"cpu_profile", p},
                   {"ordinary_timing_sample", ordinary}};
  }
  auto basis = phase;
  basis.erase("roles");
  basis.erase("complete");
  basis.erase("invalid_reasons");
  Json result = {
      {"schema", "turtle.attempt-report.v4"},
      {"success", success},
      {"ordinary_timing_sample", !perf_requested},
      {"perf_counters_requested", perf_counters},
      {"perf_complete", perf_reasons.empty()},
      {"perf_invalid_reasons", perf_reasons},
      {"phase_complete", phase.at("complete")},
      {"phase_invalid_reasons", phase.at("invalid_reasons")},
      {"phase_basis", basis},
      {"network_complete", network.value("availability", "") == "available" &&
                               network_reasons.empty()},
      {"network_invalid_reasons", network_reasons},
      {"invalid_reasons", reasons},
      {"roles", roles},
      {"captures", observations},
      {"qdisc_drops", drops},
      {"network_availability",
       network.value("availability", std::string("missing"))}};
  measurements(result);
  artifact::save(root / "analysis.json", result);
  return result;
}
std::filesystem::path attempt_directory(const std::filesystem::path &root,
                                        const std::filesystem::path &declared) {
  namespace fs = std::filesystem;
  if (declared.parent_path() != "attempts" || declared.filename().empty() ||
      declared.filename() == "." || declared.filename() == ".." ||
      declared.native().find('\0') != std::string::npos ||
      fs::canonical(root / declared).lexically_relative(fs::canonical(root)) != declared)
    throw std::runtime_error("attempt_directory_outside_run");
  return root / declared;
}
bool regenerate(const std::filesystem::path &root) {
  auto manifest = artifact::load(root / "manifest.json");
  if (manifest.at("schema") == "turtle.manifest.v3")
    return regenerate_lifecycle(root, manifest);
  if (manifest.at("schema") != "turtle.manifest.v2")
    throw std::runtime_error("unsupported_manifest_schema");
  bool valid = manifest.at("status") == "complete" &&
               manifest.at("attempts").size() == manifest.at("order").size();
  Json rows = Json::array();
  for (const auto &a : manifest.at("attempts")) {
    auto r = attempt(attempt_directory(root, a.at("directory").get<std::string>()),
                     a.value("error", Json(nullptr)));
    bool complete = r.at("success") == true && r.at("phase_complete") == true &&
                    r.at("perf_complete") == true &&
                    (manifest.at("spec").at("network") == "loopback" ||
                     r.at("network_complete") == true);
    valid = valid && complete;
    rows.push_back({{"directory", a.at("directory")},
                    {"complete", complete},
                    {"success", r.at("success")},
                    {"phase_complete", r.at("phase_complete")},
                    {"network_complete", r.at("network_complete")},
                    {"perf_complete", r.at("perf_complete")}});
  }
  artifact::save(root / "analysis.json", {{"schema", "turtle.run-analysis.v1"},
                                          {"complete", valid},
                                          {"attempts", rows}});
  return valid;
}
} // namespace turtle::analysis
