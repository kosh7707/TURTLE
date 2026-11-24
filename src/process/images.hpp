#pragma once
#include "artifact/json.hpp"
#include "process/process.hpp"
#include <sys/types.h>
namespace turtle::process {
// Owned by one attempt. Destroy after endpoint teardown, outside TLS timing.
class ImageSnapshots {
public:
  ImageSnapshots() = default;
  ~ImageSnapshots();
  ImageSnapshots(const ImageSnapshots &) = delete;
  ImageSnapshots &operator=(const ImageSnapshots &) = delete;
  artifact::Json collect(pid_t launcher, pid_t participant,
                         Deadline until = deadline(30), int cancel_fd = -1);

private:
  pid_t monitor_ = -1;
};
// Validates the raw inventory and returns the address/PID-independent build
// key. This is deliberately usable on an offline host with none of these
// binaries.
artifact::Json image_key(const artifact::Json &inventory, pid_t participant);
} // namespace turtle::process
