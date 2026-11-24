#pragma once
#include <nlohmann/json.hpp>
#include <string>
namespace turtle::native {
nlohmann::json analyze_evidence(const std::string &ndjson,
                                const nlohmann::json &context);
}
