#pragma once

// Inspect the host and select an available CPU. Does not run benchmarks or
// change global governor, boost, clock, or machine security settings.
#include "model/model.hpp"

#include <string>
#include <vector>

namespace turtle::model {
struct RunConfig;
}

namespace turtle::capability {

model::Environment inspect_environment();
// Hash only stable host topology and policy facts.  Diagnostic warnings and
// point-in-time load observations deliberately do not identify an experiment.
std::string stable_environment_hash(const model::Environment& environment);
bool pin_to_cpu(int cpu, std::string& explanation);
// Select three CPUs for ordinary TLS or four when config.lookup.enabled.
// An explicit shortage is an error; only explicit no-affinity permits -1.
void choose_cpus(model::RunConfig& config, const model::Environment& environment);
// Describe what setup-time placement cannot establish for the selected role
// CPUs.  This is pure so topology fixtures never consult the current host.
std::vector<std::string> cpu_selection_warnings(const model::RunConfig& config,
                                                const model::Environment& environment);

} // namespace turtle::capability
