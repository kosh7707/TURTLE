#pragma once

#include "report/network_evidence.hpp"

#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace turtle::report {

struct RepeatedStudyInput {
    std::filesystem::path root;
    std::filesystem::path manifest;
    std::string namespace_status = "unverified";
    std::optional<std::filesystem::path> batch_namespace;
    std::vector<std::filesystem::path> listed_run_roots;
    std::vector<std::filesystem::path> discovered_run_roots;
    bool coverage_complete = false;
    std::vector<std::string> reasons;
};

struct RepeatedRunInput {
    std::filesystem::path root;
    std::optional<std::filesystem::path> ledger_path;
    std::optional<AuthoritativeLedger> ledger;
    std::string namespace_status = "unverified";
    std::filesystem::path batch_namespace;
    std::optional<std::uint64_t> batch;
    std::optional<std::uint64_t> manifest_batch;
    std::vector<std::string> reasons;
};

struct RepeatedContextInput {
    std::filesystem::path run_root;
    std::filesystem::path source;
    std::uint64_t sample = 0;
    std::string role;
    std::uint64_t batch = 0;
    std::optional<std::size_t> measured_connections;
    std::size_t warmups = 0;
    bool raw_valid = false;
    bool peer_verified = false;
    bool peer_valid = false;
    bool lookup_scenario = false;
    bool comparison_condition_complete = false;
    std::vector<std::string> comparison_exclusion_reasons;
    std::optional<std::string> parent_status;
    nlohmann::json dimensions;
    std::vector<nlohmann::json> partitions;
    std::vector<std::string> reasons;
};

nlohmann::json repeated_context_summary(
    std::string selection_scope, std::vector<RepeatedStudyInput> studies,
    std::vector<RepeatedRunInput> runs, std::vector<RepeatedContextInput> contexts);

} // namespace turtle::report
