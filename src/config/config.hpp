#pragma once

// Parse CLI/profile input before measurement; no TLS or instrumentation here.
#include "model/model.hpp"

#include <string>

namespace turtle::config {

struct Command {
    enum class Action { Run, Capabilities, Help } action = Action::Run;
    model::RunConfig run;
};

Command parse(int argc, char** argv);
std::string usage();

}  // namespace turtle::config
