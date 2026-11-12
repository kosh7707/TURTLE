#pragma once
#include "model/run_config.hpp"
namespace turtle::lifecycle {
// Owns local resources only. A null entry selects an explicit shared module.
int run_endpoint(model::RunConfig config, AdapterEntry builtin = nullptr);
} // namespace turtle::lifecycle
