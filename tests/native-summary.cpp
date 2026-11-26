#include "native/stream_summary.hpp"
#include <cerrno>
#include <iostream>
#include <sstream>

using turtle::artifact::Json;
using turtle::native::detail::print_summary;

int main() try {
  Json row = {
      {"purpose", "sample"}, {"directory", "attempt-1"}, {"task_success", true},
      {"application_exchange", "verified"},
      {"qualification", "unknown"}, {"qualified", false}, {"pmu_status", "unsupported"},
      {"benchmark_timing_ns", 132}, {"prepared_start", {{"verified", true}}},
      {"network", {{"verified", nullptr}, {"capture_verified", nullptr}}},
      {"requested_metrics", Json::object()},
      {"participants", {{"server", {{"facts", Json::object()}}}, {"client", {
          {"timing", {{"wall_ns", 132}, {"end", {{"name", "read_return"}, {"message", "SAD1"}}}}},
          {"metrics", {{"authentication", nullptr}, {"tls_flights", nullptr}}},
          {"status", "verified"}}}}}};
  Json report = {{"measured_role", "client"}, {"samples", 1}, {"successful_measurements", 1},
                 {"qualified_samples", 0}, {"attempts", {row}}};
  auto render = [&](const char *task = "S2") {
    std::ostringstream out;
    print_summary(out, report, task);
    return out.str();
  };
  auto contains = [](const std::string &s, const std::string &part) {
    if (s.find(part) == s.npos)
      throw std::runtime_error("Missing '" + part + "' in summary:\n" + s);
  };
  auto &sample = report.at("attempts").front();
  for (auto status : {"unsupported", "partial", "multiplexed", "not_collected"}) {
    sample["pmu_status"] = status;
    std::string s = render();
    contains(s, "0 benchmark-qualified; task success 1/1");
    contains(s, "attempt-1 (diagnostic only): elapsed 132 ns (hs_begin -> SAD1.first_read_return)");
    contains(s, "auth evidence unconfirmed; full flight attribution unconfirmed");
    contains(s, std::string("Most common exclusion (1 sample(s)): PMU ") + status);
  }
  auto &timing = sample["participants"]["client"]["timing"];
  timing["end_label"] = "last_read_return";
  contains(render(), "hs_begin -> SAD1.last_read_return");
  timing.erase("end_label");
  sample["qualification"] = "cf_transport_receive_unobserved";
  contains(render(), "S2 server CF receive not observed");
  sample["qualification"] = "unknown";
  sample["pmu_status"] = "unsupported";
  auto &start = sample["participants"]["client"]["timing"]["begin"];
  start = {{"pmu_reason", "pmu_not_built"}, {"pmu_errno", 0}};
  contains(render(), "install a PMU-enabled TURTLE SDK for the measured role");
  for (int denied : {EACCES, EPERM}) {
    start = {{"pmu_reason", "cycles_open_failed"}, {"pmu_errno", denied}};
    contains(render(), "check perf-event access for the measured process");
  }
  for (const auto &reason : {Json(nullptr), Json("untrusted custom message")}) {
    start = {{"pmu_reason", reason}, {"pmu_errno", EACCES}};
    contains(render(), "check hardware counter availability and the measured interval");
    if (render().find("untrusted custom message") != std::string::npos)
      throw std::runtime_error("participant text leaked into PMU guidance");
  }
  sample["pmu_status"] = "missing";
  auto &end = sample["participants"]["client"]["timing"]["end"];
  end.update(Json{{"pmu_reason", "counter_group_read_failed"}, {"pmu_errno", EPERM}});
  contains(render(), "PMU missing (access denied)");
  sample["qualification"] = "transport_hook_unconfirmed";
  sample["measured_transport_hook"] = {{"reason", "hook_unobserved"}};
  contains(render(), "check both I/O directions on the measured role");
  sample["qualification"] = "unknown";
  sample["requested_metrics"]["authentication"] =
      {{"required", true}, {"available", nullptr}, {"metric", "authentication"}};
  contains(render(), "required metric authentication not confirmed");
  sample["requested_metrics"] = Json::object();
  sample["benchmark_timing_ns"] = nullptr;
  sample["prepared_start"]["verified"] = nullptr;
  contains(render(), "local elapsed 132 ns");
  contains(render(), "prepared start unconfirmed");

  // Warmups and diagnostics cannot become example timings or sample exclusions.
  Json warm = row, good = row, missing = row;
  warm.update(Json{{"purpose", "warmup"}, {"warmup_allows_measurement", false},
                   {"qualification", "warmup_only"}, {"warmup_assessment", "unsupported"}});
  good.update(Json{{"qualified", true}, {"qualification", "qualified"},
                   {"pmu_status", "available"}, {"directory", "attempt-4"}});
  missing["task_success"] = false;
  report.update(Json{{"samples", 4}, {"qualified_samples", 1}, {"successful_measurements", 3},
                     {"attempts", {warm, row, missing, good, row, {{"purpose", "diagnostic"}}}}});
  std::string s = render();
  contains(s, "1 benchmark-qualified; task success 3/4");
  contains(s, "attempt-4 (qualified): elapsed 132 ns");
  contains(s, "Most common exclusion (2 sample(s)): PMU unsupported");
  report.update(Json{{"samples", 0}, {"successful_measurements", 0}, {"qualified_samples", 0},
                     {"attempts", {warm}}});
  contains(render(), "Stopped in warmup: TLS operation unsupported");
  report["attempts"].front()["participants"]["server"]["facts"]["server_first"] = false;
  contains(render(), "Stopped in warmup: server early send unsupported");
  contains(render("S0"), "Stopped in warmup: TLS operation unsupported");
  if (render().find("elapsed") != std::string::npos)
    throw std::runtime_error("warmup misreported as a timing sample");
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
