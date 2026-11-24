#pragma once
#include "artifact/json.hpp"

namespace turtle::native {
// Replay only. Nothing in a capture is a TLS-call or an application timestamp.
artifact::Json analyze_packets(const std::filesystem::path &network_dir,
                               const artifact::Json &raw_attempt,
                               const artifact::Json &participants);
} // namespace turtle::native
