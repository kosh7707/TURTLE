#pragma once
#include "observation/observation.hpp"
#include "spec/spec.hpp"
#include <string>
namespace turtle {
void save_events(const Spec&, const Observer&, const turtle_support&, const std::string& failure);
void save_stream(const std::string&, const std::vector<std::uint8_t>&);
} // namespace turtle
