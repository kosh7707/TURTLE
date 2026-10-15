#pragma once

#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <map>
#include <string>
#include <vector>

namespace turtle::report {

enum class NetworkTopology { tls_only_3ns, tls_3ns_or_legacy_4ns, lookup_4ns };

struct NetworkAttempt {
    std::uint64_t id = 0;
    bool started = false;
    std::string status;
    nlohmann::json observation_ids = nlohmann::json::array();
};

struct NetworkEvidence {
    bool present = false;
    nlohmann::json condition_identity = nullptr;
    nlohmann::json observations = nlohmann::json::object();
    nlohmann::json integrity;
};

struct AuthoritativeLedger {
    std::filesystem::path root;
    std::size_t requested = 0;
    bool partial = false;
    std::vector<nlohmann::json> rows;
    std::map<std::uint64_t, NetworkAttempt> attempts;
    nlohmann::json run_summary = nullptr;
};

AuthoritativeLedger read_authoritative_ledger(const std::filesystem::path& path);

NetworkEvidence read_network_evidence(const std::filesystem::path& root,
                                      NetworkTopology expected_topology,
                                      const std::vector<NetworkAttempt>& attempts);

} // namespace turtle::report
