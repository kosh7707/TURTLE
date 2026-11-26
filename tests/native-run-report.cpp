#include "native/run_report.hpp"
#include <iostream>
#include <stdexcept>

using turtle::artifact::Json;
using turtle::native::detail::finalize_run_report;

int main() try {
  const Json manifest = {{"status", "complete"}, {"profile", {
      {"target", {{"role", "client"}}}, {"warmups", 1}, {"repetitions", 2},
      {"required_metrics", {"cpu_samples"}}}}};
  const Json sample = {
      {"purpose", "sample"}, {"operation_ok", true}, {"task_success", true},
      {"eligible", true}, {"qualified", true}, {"qualification", "qualified"},
      {"required_metrics_available", true},
      {"requested_metrics", {{"cpu_samples", Json::object()}}}};
  Json no_hook = sample;
  no_hook.update(Json{{"eligible", false}, {"qualified", false},
                      {"qualification", "transport_hook_unconfirmed"}});
  Json warmup = sample;
  warmup.update(Json{{"purpose", "warmup"}, {"operation_ok", false},
                     {"eligible", false}, {"qualified", false},
                     {"qualification", "decision_required"}});
  const Json attempts = Json::array({{{"purpose", "capability"}}, warmup,
                                     sample, no_hook, {{"purpose", "diagnostic"}}});
  Json diagnostic = {{"availability", "available"}, {"sample_count", 3},
                     {"prepared_start", true}, {"scope", "prepared_scenario"}};
  const auto report = finalize_run_report(manifest, true, attempts, diagnostic);
  const auto &rows = report.at("attempts");
  if (report.at("complete") != true || report.at("samples") != 2 ||
      report.at("successful_measurements") != 2 || report.at("qualified_samples") != 1 ||
      rows.at(0).at("qualification") != "capability_only" ||
      rows.at(1).at("warmup_assessment") != "decision_required" ||
      rows.at(1).at("warmup_allows_measurement") != true ||
      rows.at(2).at("requested_metrics").at("cpu_samples").at("available") != true ||
      rows.at(4).at("qualification") != "diagnostic_only" ||
      rows.at(4).at("cpu_samples") != diagnostic)
    throw std::runtime_error("prepared diagnostic or non-sample counting changed");

  // Real profiling data without a prepared start cannot qualify a sample.
  diagnostic.update(Json{{"prepared_start", nullptr}, {"scope", "local_diagnostic_only"}});
  const auto local = finalize_run_report(manifest, true, attempts, diagnostic);
  const auto &samples = local.at("attempts");
  const auto &metric = samples.at(2).at("requested_metrics").at("cpu_samples");
  if (local.at("complete") != false || local.at("collection_complete") != true ||
      local.at("successful_measurements") != 2 || local.at("qualified_samples") != 0 ||
      !metric.at("available").is_null() || metric.at("reason") != "unverified_diagnostic_start" ||
      samples.at(2).at("ordinary_qualified_without_diagnostic") != true ||
      samples.at(2).at("qualification") != "required_diagnostic_missing" ||
      samples.at(3).at("ordinary_qualified_without_diagnostic") != false ||
      samples.at(3).at("qualification") != "transport_hook_unconfirmed")
    throw std::runtime_error("local-only diagnostic changed task success or exclusion reasons");
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
