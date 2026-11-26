#pragma once
#include "artifact/json.hpp"
#include <algorithm>
#include <cerrno>
#include <map>
#include <ostream>

namespace turtle::native::detail {
using artifact::Json;

// Describe an observed obstacle, not a new qualification policy. The JSON
// remains the source of truth, including for replay of historical attempts.
inline std::string exclusion_hint(const Json &row, const std::string &task, const std::string &role) {
  const std::string q = row.value("warmup_assessment", row.at("qualification").get<std::string>());
  if (q == "transport_hook_unconfirmed") {
    const auto &reason = row.at("measured_transport_hook").at("reason");
    return "target transport hook unconfirmed (" + reason.get<std::string>() +
           "); check both I/O directions on the measured role, from before READY through END";
  }
  if (q == "unsupported") {
    if ((task == "S2" || task == "S4") &&
        row.at("participants").at("server").at("facts").value("server_first", Json(nullptr)) == false)
      return "server early send unsupported; provide a real pre-CF server write to measure this task";
    return "TLS operation unsupported; check the selected task's operation callbacks in the participant evidence";
  }
  if (q == "failed")
    return "attempt failed; check attempt.error and participant stderr";
  if (q == "invalid" || q == "contradicted")
    return q + " evidence; inspect the participant status and events";
  if (row.at("task_success") != true) {
    std::string known = row.at("application_exchange") == "verified" ? "application bytes matched, but " : "";
    return known + "task order not confirmed; check both roles' TLS events or use turtle_run_endpoint";
  }
  if (row.at("prepared_start").at("verified") != true)
    return "prepared start unconfirmed; check both roles' READY before TLS entry";
  if (q == "cf_transport_receive_unobserved")
    return "S2 server CF receive not observed; greeting or handshake completion cannot substitute";
  for (const auto &[key, m] : row.at("requested_metrics").items()) {
    if (m.at("required") == true && m.at("available") != true && m.at("metric") != "pmu")
      return "required metric " + m.at("metric").get<std::string>() +
             (m.at("available") == false ? " contradicted" : " not confirmed") +
             "; check its requested_metrics reason";
  }
  if (row.at("network").at("verified") == false ||
      row.at("network").at("capture_verified") == false)
    return "network condition unverified; check applied network and capture evidence";
  const auto pmu = row.at("pmu_status").get<std::string>();
  if (pmu == "unsupported" || pmu == "partial" || pmu == "missing") {
    const auto &timing = row.at("participants").at(role).at("timing");
    for (const char *edge : {"begin", "end"}) {
      auto stamp = timing.find_member(edge);
      if (!stamp || !stamp->is_object())
        continue;
      const auto reason = stamp->find_member("pmu_reason");
      if (!reason)
        continue;
      if (pmu == "unsupported" && *reason == "pmu_not_built")
        return "PMU unsupported (not built); install a PMU-enabled TURTLE SDK for the measured role";
      const auto error = stamp->find_member("pmu_errno");
      const bool counter_failure = *reason == "cycles_open_failed" || *reason == "instructions_open_failed" ||
                                   *reason == "group_setup_failed" || *reason == "counter_group_read_failed";
      if (counter_failure && error && (*error == EACCES || *error == EPERM))
        return "PMU " + pmu + " (access denied); check perf-event access for the measured process";
    }
  }
  if (pmu == "partial" || pmu == "multiplexed")
    return "PMU " + pmu + "; check cycles and instructions coverage across the measured interval";
  if (pmu != "available" && !row.at("benchmark_timing_ns").is_null())
    return "PMU " + pmu + "; check hardware counter availability and the measured interval";
  return "qualification not established; inspect the attempt's participant and required metric results";
}

inline void print_example(std::ostream &out, const Json &row, const std::string &role) {
  const auto &dut = row.at("participants").at(role);
  const auto &timing = dut.at("timing");
  const bool qualified = row.at("qualified") == true;
  out << row.at("directory").get<std::string>() << " ("
      << (qualified ? "qualified" : "diagnostic only") << "): ";
  if (!timing.at("wall_ns").is_null() && dut.at("status") != "invalid") {
    const auto &end = timing.at("end");
    const auto name = end.at("name").get<std::string>();
    out << (row.at("benchmark_timing_ns").is_null() ? "local elapsed " : "elapsed ")
        << timing.at("wall_ns") << " ns (hs_begin -> ";
    if (end.value("message", Json(nullptr)).is_string())
      out << end.at("message").get<std::string>() << '.';
    if (name == "read_return")
      out << timing.value("end_label", "first_read_return");
    else if (name == "write_accepted")
      out << "final_write_accept";
    else
      out << name;
    out << ')';
  } else {
    out << "elapsed unavailable";
  }
  const auto evidence = [&](const char *key) {
    const auto &value = dut.at("metrics").at(key);
    if (value == true)
      return "confirmed";
    if (value == false)
      return "contradicted";
    return "unconfirmed";
  };
  out << "; PMU " << row.at("pmu_status").get<std::string>()
      << " (target thread, user space); auth evidence " << evidence("authentication")
      << "; full flight attribution " << evidence("tls_flights") << '\n';
}

inline void print_summary(std::ostream &out, const Json &report, const std::string &task) {
  const auto &role = report.at("measured_role").get_ref<const std::string &>();
  const auto total = report.at("samples").get<std::size_t>();
  out << role << ' ' << task << ": " << total << " sample(s); "
      << report.at("qualified_samples") << " benchmark-qualified; task success "
      << report.at("successful_measurements") << '/' << total << '\n';
  const Json *example = nullptr, *warmup = nullptr;
  auto rank = [&](const Json &row) {
    if (row.at("qualified") == true) return 3;
    if (!row.at("benchmark_timing_ns").is_null()) return 2;
    const auto &dut = row.at("participants").at(role);
    return dut.at("status") != "invalid" && !dut.at("timing").at("wall_ns").is_null() ? 1 : 0;
  };
  std::map<std::string, size_t> exclusions;
  for (const auto &row : report.at("attempts")) {
    if (row.at("purpose") != "sample") {
      if (row.at("purpose") == "warmup" && row.at("warmup_allows_measurement") != true)
        warmup = &row;
      continue;
    }
    if (!example || rank(row) > rank(*example))
      example = &row;
    if (row.at("qualified") != true)
      ++exclusions[exclusion_hint(row, task, role)];
  }
  if (example)
    print_example(out, *example, role);
  if (!exclusions.empty()) {
    auto most = std::max_element(exclusions.begin(), exclusions.end(),
                                 [](const auto &a, const auto &b) { return a.second < b.second; });
    out << "Most common exclusion (" << most->second << " sample(s)): " << most->first << '\n';
  } else if (!total && warmup) {
    out << "Stopped in warmup: " << exclusion_hint(*warmup, task, role) << '\n';
  }
}
} // namespace turtle::native::detail
