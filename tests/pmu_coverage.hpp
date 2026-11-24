#pragma once
#include "process/process.hpp"

// Copy an already completed run and change only the PMU scheduling evidence.
// This deterministic qualification test does not claim real multiplex numbers.
inline void test_partial_coverage(const std::filesystem::path &out,
                                  const std::filesystem::path &copy,
                                  const std::string &cli) {
  namespace fs = std::filesystem;
  using namespace turtle;
  auto require = [](bool ok, const char *why) { if (!ok) throw std::runtime_error(why); };
  fs::copy(out, copy, fs::copy_options::recursive);
  auto m = artifact::load(copy / "manifest.json");
  auto &cfg = m.at("spec").at("configurations").at(0);
  require(cfg.at("raw_coverage_contract") == "partial-decision.v1", "missing policy version");
  // Warmup and first measurement are partial; second measurement is a full
  // actual sample. A diagnostic must not discard it merely due to scheduling.
  for (std::size_t i = 0; i < 2; ++i) {
    auto &a = m.at("attempts").at(i);
    auto path = copy / a.at("directory").get<std::string>() / "client/counters.json";
    auto raw = artifact::load(path);
    auto halve = [](artifact::Json &pair) {
      for (auto edge : {"begin", "end"})
        if (pair.at(edge).at("available") == true)
          pair[edge]["time_running_ns"] = artifact::integer(pair.at(edge).at("time_enabled_ns")) / 2;
    };
    for (auto &e : raw.at("events")) halve(e);
    halve(raw.at("scenario"));
    artifact::save(path, raw);
    a["artifacts_sha256"]["client/counters.json"] = process::digest(path);
  }
  artifact::save(copy / "manifest.json", m);
  auto replay = [&] { return process::command({cli, "analyze", copy.string()}); };
  require(replay().at("returncode") != 0, "unresolved run reported qualified");
  const auto summary = artifact::load(copy / "analysis.json");
  require(summary.at("qualification") == "decision_required" &&
          summary.at("decision_required_measurements") == 1 &&
          summary.at("decision_required_attempts") == 2 &&
          summary.at("eligible_measurements") == 1 && summary.at("collection_complete") == true,
          "wrong partial coverage aggregate or warmup gate");
  for (std::size_t i = 0; i < 2; ++i) {
    const auto r = artifact::load(copy / m.at("attempts").at(i).at("directory").get<std::string>() / "analysis.json");
    const auto &scope = r.at("roles").at("client").at("counters").at("operations").at("scenario");
    require(r.at("qualification") == "decision_required" && r.at("invalid_reasons").empty() &&
            r.at("success") == true && r.at("configuration_matches") == true &&
            r.at("required_metrics_valid").is_null() && r.at("ordinary_timing_sample") == false &&
            scope.at("cycles").at("value").is_null() && scope.at("instructions").at("value").is_null() &&
            scope.at("cycles_raw").at("value").is_number_unsigned() &&
            r.at("pmu_coverage").at("running_fraction") > 0.49 &&
            r.at("pmu_coverage").at("running_fraction") < 0.51, "partial evidence lost or promoted");
  }
  cfg.erase("raw_coverage_contract");
  artifact::save(copy / "manifest.json", m);
  require(replay().at("returncode") != 0 &&
          artifact::load(copy / "analysis.json").at("eligible_measurements") == 0,
          "older warmup classification silently changed");
}
