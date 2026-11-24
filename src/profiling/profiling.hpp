#pragma once
#include "process/process.hpp"
namespace turtle::profiling {
using artifact::Json;
process::Environment environment(const std::filesystem::path &);
void validate_settings(const Json &);
Json probe(const Json &, int cancel_fd);
Json settings(const Json &);
process::Args prepare(const std::filesystem::path &, const Json &);
void finish(const std::filesystem::path &, int);
Json parse_samples(const std::string &);
Json distribution(const Json &);
Json window(const Json &, std::uint64_t, std::uint64_t);
// Preserve legacy decoder receipts even when no endpoint could be assessed.
void save_attempt_report(const std::filesystem::path &attempt, Json &report);
Json analyze(const std::filesystem::path &, const Json &summary,
             const Json &events, const Json &phases);
} // namespace turtle::profiling
