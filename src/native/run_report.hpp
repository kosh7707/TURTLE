#pragma once
#include "artifact/json.hpp"

namespace turtle::native::detail {
// Finalize already assessed attempts. No filesystem access: run, replay and
// retry use the same result after the caller has verified the raw inventory.
artifact::Json finalize_run_report(const artifact::Json &manifest,
                                   bool cpu_samples_required,
                                   artifact::Json attempts,
                                   artifact::Json diagnostic);
} // namespace turtle::native::detail
