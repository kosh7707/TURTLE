#pragma once
#include "artifact/json.hpp"
namespace turtle::native {
// Inputs are reports of validated, complete evidence lines up to the
// watermarks. null is absence of sufficient proof, never an affirmative
// capability.
artifact::Json pre_cf_extent(const artifact::Json &client,
                             const artifact::Json &server,
                             std::size_t greeting_size, bool stock_server);
bool pre_cf_arrived(const artifact::Json &extent, uint64_t queued);
// Bind the encrypted bytes actually consumed by the known probe client through
// successful greeting validation to the already submitted sender prefix.
artifact::Json pre_cf_delivery(const artifact::Json &client_validated,
                               const artifact::Json &server_frozen,
                               const artifact::Json &extent, bool stock_server,
                               uint64_t queued);
} // namespace turtle::native
