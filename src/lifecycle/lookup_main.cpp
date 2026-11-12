#include "config/config.hpp"
#include "lifecycle/lookup_runtime.hpp"
#include <iostream>
int main(int argc, char** argv) {
    try {
        auto command = turtle::config::parse(argc, argv, turtle::Role::Server);
        if (command.action == turtle::config::Command::Action::Help) {
            std::cout << "turtle-lookup: independent synthetic lookup service\n"
                      << turtle::config::usage();
            return 0;
        }
        return turtle::lifecycle::detail::run_lookup_service(std::move(command.run));
    } catch (const std::exception& error) {
        std::cerr << "lookup: " << error.what() << '\n';
        return 1;
    }
}
