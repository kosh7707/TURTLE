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

std::vector<std::uint8_t> load_serialized_context(const model::RunConfig& config, Role role);

int run_tls_role(const model::RunConfig& config, Role role, std::uint64_t sample,
                 const std::string& directory, int listener, const tcp::DialAddress& address,
                 int control_fd, control::Deadline deadline, std::span<const std::uint8_t> saved,
                 const lookup::Snapshot* reference, const lookup::Snapshot* initial,
                 std::vector<int> lookup_sockets = {});

} // namespace turtle::lifecycle::detail
