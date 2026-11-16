#pragma once
#include "observation/observation.hpp"
#include "spec/spec.hpp"
#include <vector>
namespace turtle {
struct ObjectCache {
    std::vector<std::uint8_t> object;
};
ObjectCache prepare_lookup(const Spec&, Observer&);
} // namespace turtle
