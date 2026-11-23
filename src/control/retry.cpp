#include "control/controller.hpp"
#include "artifact/json.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace turtle::control {
namespace fs = std::filesystem;
using artifact::Json;
namespace {
void require(bool ok, const char *why) {
  if (!ok)
    throw std::runtime_error(why);
}
template <class Predicate>
const Json &unique(const Json &rows, Predicate matches, const char *why) {
  require(rows.is_array(), why);
  auto it = std::find_if(rows.begin(), rows.end(), matches);
  require(it != rows.end() && std::none_of(std::next(it), rows.end(), matches), why);
  return *it;
}
bool inside(const fs::path &path, const fs::path &root) {
  auto relative = path.lexically_relative(root);
  return !relative.empty() && *relative.begin() != "..";
}
Json load_inside(const fs::path &root, const fs::path &relative) {
  auto file = fs::canonical(root / relative);
  require(inside(file, root), "retry_evidence_outside_source_run");
  return artifact::load(file);
}
} // namespace

int retry(const fs::path &old_run, const std::string &failed_id,
          const fs::path &output, const std::string &self, int cancel) {
  const auto root = fs::canonical(old_run);
  const auto destination = fs::weakly_canonical(fs::absolute(output));
  require(!inside(destination, root), "retry_output_inside_source_run");
  const auto m = load_inside(root, "manifest.json");
  require(m.at("schema") == "turtle.manifest.v3", "retry_requires_manifest_v3");
  const auto &status = m.at("status");
  require(status == "complete" || status == "failed" || status == "interrupted",
          "retry_source_not_finalized");
  auto same_id = [&](const Json &r) { return r.at("run_id") == failed_id; };
  const auto &a = unique(m.at("attempts"), same_id, "retry_attempt_not_unique_or_missing");
  require(a.at("purpose") == "measurement", "retry_requires_measurement");
  const auto &order = m.at("order");
  const auto &slot = unique(order, [&](const Json &s) {
    return s.at("purpose") == "measurement" && s.at("repeat") == a.at("repeat") &&
           s.at("configuration") == a.at("configuration");
  }, "retry_measurement_not_scheduled");
  auto spec = m.at("spec");
  const auto config = unique(spec.at("configurations"), [&](const Json &c) {
    return c.at("id") == slot.at("configuration");
  }, "retry_configuration_not_unique_or_missing");
  require(artifact::integer(slot.at("repeat")) < artifact::integer(spec.at("repetitions")),
          "retry_repeat_outside_schedule");

  auto index = std::distance(order.begin(), std::find(order.begin(), order.end(), slot));
  std::ostringstream suffix;
  suffix << std::setw(5) << std::setfill('0') << index;
  const auto batch = m.at("execution_id").get<std::string>();
  const auto directory = "attempts/" + suffix.str();
  require(!batch.empty() && failed_id == batch + ":" + suffix.str() &&
          a.at("directory") == directory, "retry_attempt_identity_mismatch");

  // Read the existing assessments. Calling regenerate/assess here would rewrite
  // the source run and could destroy the originally reported failure.
  auto summary = load_inside(root, "analysis.json");
  require(summary.at("schema") == "turtle.run-analysis.v2", "retry_missing_run_assessment");
  const auto &row = unique(summary.at("attempts"), same_id, "retry_missing_measurement_assessment");
  auto report = load_inside(root, fs::path(directory) / "analysis.json");
  require(row.at("purpose") == "measurement" && row.at("configuration") == config.at("id") &&
          row.at("directory") == directory && report.at("schema") == "turtle.attempt-report.v4" &&
          report.at("run_id") == failed_id && report.at("purpose") == "measurement" &&
          row.at("success") == report.at("success") && row.at("complete") == report.at("eligible"),
          "retry_assessment_identity_mismatch");
  require(report.at("eligible") == false && report.at("invalid_reasons").is_array() &&
          !report.at("invalid_reasons").empty(), "retry_requires_failed_measurement");
  spec["configurations"] = Json::array({config});
  spec["baseline"] = config.at("id");
  spec["repetitions"] = 1;
  spec["retry_of"] = {{"execution_id", batch}, {"run_id", failed_id}, {"source", root.string()}};

  // Opaque adapter arguments and environment values may contain relative paths.
  // Reuse their original base without interpreting or rewriting them.
  const auto executable = fs::absolute(self).string();
  struct RestoreDirectory {
    fs::path old = fs::current_path();
    ~RestoreDirectory() {
      std::error_code ignored;
      fs::current_path(old, ignored);
    }
  } restore;
  fs::current_path(m.at("provenance").at("working_directory").get<std::string>());
  return execute_spec(std::move(spec), destination, executable, cancel);
}
} // namespace turtle::control
