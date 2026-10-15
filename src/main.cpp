#include "capability/capability.hpp"
#include "config/config.hpp"
#include "lifecycle/lifecycle.hpp"
#include "measure/measure.hpp"
#include <exception>
#include <iostream>
int main(int argc, char** argv) {
    try {
        auto command = turtle::config::parse(argc, argv);
        if (command.action == turtle::config::Command::Action::Help) {
            std::cout << turtle::config::usage();
            return 0;
        }
        if (command.action == turtle::config::Command::Action::Capabilities) {
            const auto environment = turtle::capability::inspect_environment();
            turtle::measure::Meter meter(
                command.run.mode, command.run.perf, command.run.perf_scope);
            const auto& caps = meter.capabilities();
            std::cout << "kernel: " << environment.kernel << "\nCPU: " << environment.cpu_model
                      << "\ncompiler: " << environment.compiler
                      << "\nallowed logical CPUs: " << environment.allowed_cpus.size()
                      << "\nverified physical cores: " << environment.physical_cpus.size()
                      << "\ngovernor: " << environment.governor << "\nboost: " << environment.boost
                      << "\nmonotonic resolution (ns): " << caps.monotonic_resolution_ns
                      << "\nthread CPU resolution (ns): " << caps.thread_cpu_resolution_ns
                      << "\nperf requested scope: "
                      << turtle::model::name(caps.perf_requested_scope)
                      << "\nperf status: " << turtle::model::name(caps.perf_status)
                      << "\nperf effective scope: "
                      << (caps.perf_effective_scope
                              ? turtle::model::name(*caps.perf_effective_scope)
                              : "unavailable")
                      << "\nperf: " << caps.perf << " (" << caps.perf_note << ")"
                      << "\nperf_event_paranoid: "
                      << (environment.perf_event_paranoid
                              ? std::to_string(*environment.perf_event_paranoid)
                              : "unavailable")
                      << "\nheap: memory mode + adapter allocator hooks required"
                      << "\nstack: " << caps.stack_tracking << " (" << caps.stack_note << ")"
                      << "\nreceive timestamps: probed on each measured TCP connection"
                      << "\nTX/NIC timestamps, eBPF and packet capture: not implemented\n";
            for (const auto& warning : environment.warnings) {
                std::cout << "warning: " << warning << '\n';
            }
            return 0;
        }
        return turtle::lifecycle::run(command.run);
    } catch (const std::exception& error) {
        std::cerr << "turtle: " << error.what() << '\n';
        return 1;
    }
}
