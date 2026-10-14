#include "capability/capability.hpp"
#include <algorithm>
#include <cassert>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>

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
    capability::choose_cpus(disabled, {});
    assert(disabled.client_cpu == -1);
    model::RunConfig insufficient;
    try {
        capability::choose_cpus(insufficient, {});
        assert(false);
    } catch (const std::runtime_error&) {
    }
    assert(insufficient.client_cpu == -1);
    std::string explanation;
    assert(!capability::pin_to_cpu(-1, explanation));
    assert(!explanation.empty());
    if (environment.physical_cpus.size() >= 3) {
        model::RunConfig config;
        capability::choose_cpus(config, environment);
        assert(config.client_cpu != config.server_cpu && config.director_cpu != config.client_cpu);
        config.server_cpu = config.client_cpu;
        try {
            capability::choose_cpus(config, environment);
            assert(false);
        } catch (const std::runtime_error&) {
        }
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
