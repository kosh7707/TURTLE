#pragma once
#include "submission/assessment.hpp"

namespace turtle::submission {
inline const Fields result_columns{
  "auth","scenario","measured_role","purpose","attempt","connection_id","state","task_success",
  "wall_ns","wall_status","cycles","pmu_status","pmu_reason","reason","start_ns","end_ns",
  "end_event","client_pid","server_pid","case_dir","client_stderr","server_stderr","network_state"
};

struct Summary {
  unsigned attempted = 0, successes = 0, verified = 0, wall = 0, cycles = 0;
  std::string state = "passed", reason;
  void issue(const std::string &new_state, const std::string &why) {
    const auto rank = [](const std::string &s) {
      return s == "passed" ? 0 : s == "insufficient_evidence" ? 1 : s == "unsupported" ? 2 : 3;
    };
    if (rank(new_state) > rank(state)) { state = new_state; reason = why; }
  }
};

// Each connection's raw evidence is already closed before it reaches this
// spool. Publish the statistics only once the link's sample window has closed.
class CaseRows {
  fs::path file_;
  std::ofstream spool_;
public:
  explicit CaseRows(const fs::path &dir) : file_(dir / "attempts.pending.csv"), spool_(file_) {
    write_row(spool_,result_columns);
  }
  void append(const Fields &row) {
    write_row(spool_,row);
    spool_.flush();
    evidence(bool(spool_), "could not flush attempt spool");
  }
  void publish(std::ostream &results, Summary &summary, bool network_ok) {
    spool_.close();
    evidence(bool(spool_), "could not finish attempt spool");
    CsvInput input(file_);
    Record row;
    while (input.next(row)) {
      bool sample = row.at("purpose") == "sample";
      row.at("network_state") = sample ? (network_ok ? "verified" : "unverified") : "not_sample";
      if (sample) {
        ++summary.attempted;
        summary.successes += row.at("task_success") == "1";
        if (!network_ok) {
          if (row.at("state") == "passed") {
            row["state"] = "insufficient_evidence";
            row["reason"] = "sample window network evidence unavailable";
          }
          row["wall_ns"].clear(); row["cycles"].clear();
          row["start_ns"].clear(); row["end_ns"].clear();
          row["wall_status"] = "unavailable"; row["pmu_status"] = "unavailable";
          row["pmu_reason"] = "sample window network evidence unavailable";
        }
        summary.verified += row.at("state") == "passed";
        summary.wall += !row.at("wall_ns").empty();
        summary.cycles += !row.at("cycles").empty();
      }
      if (sample || row.at("task_success") != "1") summary.issue(row.at("state"),row.at("reason"));
      Fields fields;
      for (const auto &key : result_columns) fields.push_back(row.at(key));
      write_row(results,fields);
    }
    results.flush();
    evidence(bool(results), "could not publish per-connection results");
    fs::remove(file_);
  }
};
} // namespace turtle::submission
