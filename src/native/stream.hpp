#pragma once
#include "artifact/json.hpp"

namespace turtle::native {
// A warmup may collect incomplete, but real, PMU counters. That calls for a
// sample decision, not a failed setup. assess() only grants decision_required
// after the task and every other mandatory metric have been verified.
inline bool warmup_allows_measurement(const artifact::Json &assessment) {
  return assessment.at("operation_ok") == true ||
         assessment.at("qualification") == "decision_required";
}
int check(const std::filesystem::path &profile);
int execute(artifact::Json profile, const std::filesystem::path &output,
            const std::filesystem::path &self, int cancel,
            artifact::Json retry_of = nullptr);
int retry(const std::filesystem::path &, const std::string &,
          const std::filesystem::path &, const std::filesystem::path &, int);
int regenerate(const std::filesystem::path &output);
} // namespace turtle::native
