#pragma once

#include "control/control.hpp"
#include "model/run_config.hpp"
#include "transport/tcp.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace turtle::lookup {
class Snapshot;
}

namespace turtle::lifecycle::detail {

class PeerSession;

std::vector<std::uint8_t> load_serialized_context(const model::RunConfig& config, Role role);

int run_tls_role(const model::RunConfig& config, Role role, std::uint64_t sample,
                 const std::string& directory, PeerSession& session, const tcp::DialAddress& address,
                 control::Deadline deadline, AdapterEntry builtin,
                 std::span<const std::uint8_t> saved, const lookup::Snapshot* reference,
                 const lookup::Snapshot* initial);

} // namespace turtle::lifecycle::detail
