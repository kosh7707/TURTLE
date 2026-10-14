#include "config/config.hpp"
#include "lifecycle/lifecycle.hpp"
#include "capability/capability.hpp"
#include "measure/measure.hpp"
#include <iostream>
#include <exception>
int main(int argc, char** argv) {
    try {
        auto command = turtle::config::parse(argc, argv);
        if (command.action == turtle::config::Command::Action::Help) {
            std::cout << turtle::config::usage();
            return 0;
        }
        if (command.action == turtle::config::Command::Action::Capabilities) {
            const auto environment = turtle::capability::inspect_environment();
            turtle::measure::Meter meter(command.run.mode, command.run.perf);
            const auto& caps = meter.capabilities();
            std::cout << "kernel: " << environment.kernel << "\nCPU: " << environment.cpu_model
                      << "\nperf: " << caps.perf << " (" << caps.perf_note
                      << ")\nstack: " << caps.stack_tracking << " (" << caps.stack_note << ")\n";
            return 0;
        }
        return turtle::lifecycle::run(command.run);
    } catch (const std::exception& error) {
        std::cerr << "turtle: " << error.what() << '\n';
        return 1;
    }
}
