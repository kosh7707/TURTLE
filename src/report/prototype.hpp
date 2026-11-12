#pragma once
#include <nlohmann/json.hpp>
#include <vector>
namespace turtle::report {
nlohmann::json prototype_observations(const nlohmann::json& header,
                                      const std::vector<nlohmann::json>& events,
                                      std::size_t connection,
                                      const nlohmann::json* decoded = nullptr);
}
