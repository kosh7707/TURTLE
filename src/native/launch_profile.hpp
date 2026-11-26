#pragma once
#include "artifact/json.hpp"

namespace turtle::native::detail {
artifact::Json normalize_launch_profile(artifact::Json profile,
                                         const std::filesystem::path &base,
                                         const std::filesystem::path &self);
// Validate and resolve a metric name without changing its label in the report.
std::string canonical_metric_name(const std::string &name);
} // namespace turtle::native::detail
