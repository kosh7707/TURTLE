#pragma once
#include "artifact/json.hpp"
namespace turtle::artifact {
// One-sided Linux qdisc witness. Replay never executes tc or needs privileges.
Json normalized_netem(Json requested);
void verify_netem(const Json &request, const Json &network);
} // namespace turtle::artifact
