#pragma once

// Parse CLI/profile input before measurement; no TLS or instrumentation here.
#include "model/run_config.hpp"

#include <string>

namespace turtle::config {

struct Command {
    enum class Action { Run, Capabilities, Help } action = Action::Run;
    model::RunConfig run;
};

Command parse(int argc, char** argv, Role role = Role::Client);
std::string usage();

} // namespace turtle::config
