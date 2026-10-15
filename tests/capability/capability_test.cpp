#include "capability/capability.hpp"
#include "model/run_config.hpp"

#include <algorithm>
#include <cassert>
#include <string_view>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>

namespace {

turtle::model::Environment topology(std::initializer_list<int> cpus) {
    turtle::model::Environment environment;
    environment.allowed_cpus.assign(cpus);
    environment.physical_cpus.assign(cpus);
    return environment;
}

turtle::model::CpuTopology cpu_topology(
    int cpu, int package, int core,
    std::optional<std::vector<turtle::model::CpuSibling>> siblings = std::nullopt) {
    return {.cpu = cpu,
            .package_id = package,
            .core_id = core,
            .thread_siblings = std::move(siblings)};
}

bool contains_warning(const std::vector<std::string>& warnings, std::string_view fragment) {
    return std::any_of(warnings.begin(), warnings.end(), [&](const auto& warning) {
        return warning.find(fragment) != std::string::npos;
    });
}

bool selection_fails(turtle::model::RunConfig config,
                     const turtle::model::Environment& environment) {
    try {
        turtle::capability::choose_cpus(config, environment);
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

} // namespace

int main() {
    using namespace turtle;
    const auto environment = capability::inspect_environment();
    assert(!environment.kernel.empty());
    assert(!environment.compiler.empty());
    assert(!environment.environment_hash.empty());
    assert(environment.environment_hash == capability::inspect_environment().environment_hash);
    assert(environment.perf_event_paranoid ||
           !environment.perf_event_paranoid_reason.empty());
    assert(environment.cpu_topology.size() == environment.allowed_cpus.size());
    for (const int cpu : environment.physical_cpus)
        assert(std::find(environment.allowed_cpus.begin(), environment.allowed_cpus.end(), cpu) !=
               environment.allowed_cpus.end());

    model::RunConfig disabled;
    disabled.pin_cores = false;
    disabled.director_cpu = 1;
    disabled.client_cpu = 2;
    disabled.server_cpu = 3;
    disabled.ca_cpu = 4;
    capability::choose_cpus(disabled, {});
    assert(disabled.director_cpu == -1 && disabled.client_cpu == -1 &&
           disabled.server_cpu == -1 && disabled.ca_cpu == -1);

    const auto four_cores = topology({1000001, 1000002, 1000003, 1000004});
    model::RunConfig ordinary;
    capability::choose_cpus(ordinary, four_cores);
    assert(ordinary.director_cpu == 1000001);
    assert(ordinary.client_cpu == 1000002);
    assert(ordinary.server_cpu == 1000003);
    assert(ordinary.ca_cpu == -1);

    model::RunConfig lookup;
    lookup.lookup.enabled = true;
    capability::choose_cpus(lookup, four_cores);
    assert(lookup.director_cpu == 1000001);
    assert(lookup.client_cpu == 1000002);
    assert(lookup.server_cpu == 1000003);
    assert(lookup.ca_cpu == 1000004);

    model::RunConfig insufficient_tls;
    assert(selection_fails(insufficient_tls, topology({1000011, 1000012})));
    model::RunConfig insufficient_lookup;
    insufficient_lookup.lookup.enabled = true;
    assert(selection_fails(insufficient_lookup, topology({1000011, 1000012, 1000013})));

    model::RunConfig duplicate;
    duplicate.director_cpu = 1000001;
    duplicate.client_cpu = 1000001;
    assert(selection_fails(duplicate, four_cores));
    model::RunConfig disallowed;
    disallowed.director_cpu = 2000001;
    assert(selection_fails(disallowed, four_cores));

    // Supplied topology is authoritative. These synthetic CPU numbers must
    // never cause choose_cpus or warning classification to inspect this host.
    model::Environment detailed;
    detailed.allowed_cpus = {100, 102, 104, 106};
    detailed.physical_cpus = detailed.allowed_cpus;
    detailed.cpu_topology = {
        cpu_topology(100, 0, 0,
                     std::vector<model::CpuSibling>{{100, true}, {101, true}}),
        cpu_topology(102, 0, 1,
                     std::vector<model::CpuSibling>{{102, true}, {103, std::nullopt}}),
        cpu_topology(104, 0, 2, std::vector<model::CpuSibling>{{104, true}, {105, false}}),
        cpu_topology(106, 0, 3),
    };
    model::RunConfig selected;
    capability::choose_cpus(selected, detailed);
    assert(selected.director_cpu == 100 && selected.client_cpu == 102 &&
           selected.server_cpu == 104);
    const auto placement_warnings = capability::cpu_selection_warnings(selected, detailed);
    assert(contains_warning(placement_warnings, "CPU 101 outside the allowed affinity mask"));
    assert(contains_warning(placement_warnings, "CPU 103 outside the allowed affinity mask"));
    assert(contains_warning(placement_warnings, "sibling online state is unknown"));
    assert(!contains_warning(placement_warnings, "CPU 105"));
    assert(contains_warning(placement_warnings, "whole-run exclusive use is not guaranteed"));

    model::RunConfig unknown_siblings = selected;
    unknown_siblings.server_cpu = 106;
    const auto unknown_warnings =
        capability::cpu_selection_warnings(unknown_siblings, detailed);
    assert(contains_warning(unknown_warnings, "thread siblings are unknown"));

    model::Environment shared_core = detailed;
    shared_core.allowed_cpus.push_back(101);
    shared_core.physical_cpus.push_back(101);
    shared_core.cpu_topology.push_back(
        cpu_topology(101, 0, 0, std::vector<model::CpuSibling>{{100, true}, {101, true}}));
    model::RunConfig duplicate_core;
    duplicate_core.director_cpu = 100;
    duplicate_core.client_cpu = 101;
    duplicate_core.server_cpu = 102;
    assert(selection_fails(duplicate_core, shared_core));
    const auto shared_warnings =
        capability::cpu_selection_warnings(duplicate_core, shared_core);
    assert(contains_warning(shared_warnings,
                            "director and client roles share a verified physical core"));

    model::Environment unknown_topology = detailed;
    unknown_topology.cpu_topology[1].core_id.reset();
    model::RunConfig explicitly_unknown;
    explicitly_unknown.director_cpu = 102;
    explicitly_unknown.client_cpu = 100;
    explicitly_unknown.server_cpu = 104;
    assert(selection_fails(explicitly_unknown, unknown_topology));

    model::RunConfig no_affinity;
    no_affinity.pin_cores = false;
    const auto no_affinity_warnings =
        capability::cpu_selection_warnings(no_affinity, detailed);
    assert(no_affinity_warnings.size() == 1);
    assert(contains_warning(no_affinity_warnings, "role placement is not verified"));

    detailed.kernel = "kernel";
    detailed.cpu_model = "cpu";
    detailed.compiler = "compiler";
    detailed.governor = "performance";
    detailed.boost = "disabled";
    detailed.perf_event_paranoid = 2;
    const auto stable_hash = capability::stable_environment_hash(detailed);
    detailed.load_before = 123.0;
    detailed.warnings.push_back("point-in-time diagnostic");
    detailed.perf_event_paranoid_reason = "diagnostic wording changed";
    assert(capability::stable_environment_hash(detailed) == stable_hash);
    detailed.cpu_topology[0].thread_siblings->at(1).online = false;
    assert(capability::stable_environment_hash(detailed) != stable_hash);

    std::string explanation;
    assert(!capability::pin_to_cpu(-1, explanation));
    assert(!explanation.empty());
    if (environment.physical_cpus.size() >= 3) {
        model::RunConfig config;
        capability::choose_cpus(config, environment);
        assert(config.client_cpu != config.server_cpu && config.director_cpu != config.client_cpu);
        config.server_cpu = config.client_cpu;
        assert(selection_fails(config, environment));
    }
    if (!environment.allowed_cpus.empty()) {
        // Pin only the child so the test runner retains its affinity.
        const auto child = fork();
        assert(child >= 0);
        if (child == 0) {
            if (!capability::pin_to_cpu(environment.allowed_cpus.front(), explanation))
                _exit(1);
            const auto pinned = capability::inspect_environment();
            _exit(pinned.allowed_cpus.size() == 1 ? 0 : 2);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
}
