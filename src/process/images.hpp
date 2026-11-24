#pragma once
#include "artifact/json.hpp"
#include "process/process.hpp"
#include <sys/types.h>
namespace turtle::process {
// Snapshot a READY/terminal participant, never arbitrary PIDs supplied by an
// app.
artifact::Json image_inventory(pid_t launcher, pid_t participant,
                               Deadline until = deadline(30), int cancel_fd = -1);
// Validates the raw inventory and returns the address/PID-independent build
// key. This is deliberately usable on an offline host with none of these
// binaries.
artifact::Json image_key(const artifact::Json &inventory, pid_t participant);
} // namespace turtle::process
