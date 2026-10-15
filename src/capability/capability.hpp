#pragma once

// Inspect the host and select an available CPU. Does not run benchmarks or
// change global governor, boost, clock, or machine security settings.
#include "model/model.hpp"

#include <string>

namespace turtle::capability {

model::Environment inspect_environment();
bool pin_to_cpu(int cpu, std::string& explanation);
// Select three CPUs for ordinary TLS or four when config.lookup.enabled.
// An explicit shortage is an error; only explicit no-affinity permits -1.
void choose_cpus(model::RunConfig& config, const model::Environment& environment);

} // namespace turtle::capability
