#pragma once
#include "process/process.hpp"
namespace turtle::control {
using process::Args;
using process::Child;
using process::command;
using process::deadline;
using process::digest;
using process::Environment;
using process::executable;
artifact::Json run_pair(const artifact::Json &, const std::filesystem::path &,
                        const std::string &,
                        const std::map<std::string, Args> &prefixes = {},
                        const std::string &host = "127.0.0.1",
                        double timeout = 30, int cancel_fd = -1);
int execute(const std::filesystem::path &, const std::filesystem::path &,
            const std::string &executable, int cancel_fd);
} // namespace turtle::control
