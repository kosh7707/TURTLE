#include "capability/capability.hpp"

#include <algorithm>
#include <cassert>
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
