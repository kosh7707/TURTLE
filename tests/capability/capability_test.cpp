#include "capability/capability.hpp"
#include "model/run_config.hpp"
#include <algorithm>
#include <cassert>
int main() {
    using namespace turtle;
    auto host = capability::inspect_environment();
    assert(!host.kernel.empty() && !host.environment_hash.empty());
    assert(host.environment_hash == capability::inspect_environment().environment_hash);
    model::Environment one_cpu;
    one_cpu.allowed_cpus = {123};
    model::RunConfig local;
    capability::choose_cpus(local, one_cpu);
    assert(local.cpu == 123); // A remote peer never demands a second local CPU.
    local.role = Role::Server;
    capability::choose_cpus(local, one_cpu);
    assert(local.cpu == 123);
    local.pin_cores = false;
    capability::choose_cpus(local, {});
    assert(local.cpu == -1);
    local.pin_cores = true;
    local.cpu = 123;
    one_cpu.physical_cpus = {123};
    const auto unknown = capability::cpu_selection_warnings(local, one_cpu);
    assert(std::any_of(unknown.begin(), unknown.end(), [](const auto& message) {
        return message.find("physical core is not verified") != std::string::npos;
    }));
    one_cpu.cpu_topology = {{123, 0, 0, std::vector<model::CpuSibling>{{123, true}, {124, true}}}};
    const auto warnings = capability::cpu_selection_warnings(local, one_cpu);
    assert(std::any_of(warnings.begin(), warnings.end(), [](const auto& message) {
        return message.find("CPU 124 outside the allowed affinity mask") != std::string::npos;
    }));
}
