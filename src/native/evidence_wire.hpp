#pragma once
#include <nlohmann/json.hpp>
namespace turtle::native {
void evaluate_wire(const nlohmann::json &context, nlohmann::json &report);
}
