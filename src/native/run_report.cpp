#include "native/run_report.hpp"
#include "native/stream.hpp"
#include <stdexcept>
#include <utility>

namespace turtle::native::detail {
using artifact::Json;
namespace {
// eligible is the compatibility spelling of qualified in the report schema.
void exclude(Json &row, const char *reason) {
  row["eligible"] = false;
  row["qualified"] = false;
  if (reason)
    row["qualification"] = reason;
}

struct CpuSamples {
  bool required, available;
  Json reason;
};

// Function profiling is a separate diagnostic, never an ordinary PMU sample.
CpuSamples cpu_sample_status(bool required, const Json &diagnostic) {
  if (diagnostic.is_object() &&
      diagnostic.value("availability", "missing") == "available" &&
      diagnostic.contains("sample_count") &&
      diagnostic.value("prepared_start", Json(nullptr)) == true)
    return {required, true, nullptr};

  Json reason = "separate_diagnostic_missing";
  if (diagnostic.is_object())
    reason = diagnostic.value("scope", "") == "local_diagnostic_only"
                 ? Json("unverified_diagnostic_start")
                 : diagnostic.value("reason", reason);
  return {required, false, std::move(reason)};
}

void apply_cpu_samples(Json &sample, const CpuSamples &cpu) {
  auto &metrics = sample.at("requested_metrics");
  auto request = metrics.find("cpu_samples");
  if (request == metrics.end())
    return;
  (*request)["available"] = cpu.available ? Json(true) : Json(nullptr);
  (*request)["reason"] = cpu.reason;
  if (cpu.required && !cpu.available) {
    sample["ordinary_qualified_without_diagnostic"] = sample.at("eligible");
    // Keep the specific reason if ordinary evidence already excluded this row.
    exclude(sample, sample.at("eligible") == true ? "required_diagnostic_missing"
                                                 : nullptr);
    sample["operation_ok"] = false;
    sample["required_metrics_available"] = false;
  }
}
} // namespace

Json finalize_run_report(const Json &manifest, bool cpu_samples_required,
                         Json attempts, Json diagnostic) {
  const auto &profile = manifest.at("profile");
  const bool collection_complete = manifest.at("status") == "complete";
  const auto cpu = cpu_sample_status(cpu_samples_required, diagnostic);
  bool complete = collection_complete && (!cpu.required || cpu.available);
  std::size_t samples = 0, successful = 0, qualified = 0, warmups = 0;
  for (auto &row : attempts) {
    const auto &purpose = row.at("purpose");
    if (purpose == "sample") {
      apply_cpu_samples(row, cpu);
      ++samples;
      successful += row.at("task_success") == true;
      qualified += row.at("qualified") == true;
      complete = complete && row.at("operation_ok") == true;
    } else if (purpose == "warmup") {
      ++warmups;
      const bool proceed = warmup_allows_measurement(row);
      row["warmup_allows_measurement"] = proceed;
      row["warmup_assessment"] = row.at("qualification");
      exclude(row, "warmup_only");
      complete = complete && proceed;
    } else if (purpose == "diagnostic") {
      row["cpu_samples"] = diagnostic;
      exclude(row, "diagnostic_only");
    } else if (purpose == "capability") {
      exclude(row, "capability_only");
    } else {
      throw std::runtime_error("invalid_attempt_purpose");
    }
  }
  complete = complete && profile.at("repetitions") == samples &&
             profile.at("warmups") == warmups;
  return {{"cpu_samples", std::move(diagnostic)},
          {"schema", "turtle.native-run.v1"},
          {"measured_role", profile.at("target").at("role")},
          {"attempts", std::move(attempts)},
          {"qualified_samples", qualified},
          {"eligible_measurements", qualified},
          {"measurement_count", samples},
          {"successful_measurements", successful},
          {"collection_complete", collection_complete},
          {"samples", samples},
          {"complete", complete}};
}
} // namespace turtle::native::detail
