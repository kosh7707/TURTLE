#pragma once

// Compose adapter, transport, measurement, and recording lifetimes. Other
// modules must not depend on this module or choose lifecycle policy themselves.
namespace turtle::model {
struct RunConfig;
}

namespace turtle::lifecycle {

int run(const model::RunConfig& config);

} // namespace turtle::lifecycle
