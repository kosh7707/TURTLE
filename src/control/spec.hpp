#pragma once
#include "process/process.hpp"
namespace turtle::control {
using artifact::Json;
// Resolve and validate the complete plan before the first connection is opened.
Json resolve_spec(Json);
Json preflight(const Json &spec, int cancel_fd = -1);
bool requested(const Json &config, const std::string &metric);
bool server_first(const Json &config);
process::Args endpoint_args(const Json &config, const std::string &role,
                            const std::string &purpose, process::Args flags);
} // namespace turtle::control
