#pragma once

#include "control/control.hpp"
#include "model/run_config.hpp"
#include <span>

namespace turtle::lifecycle::detail {

// A peer session borrows its TCP control socket. No control work is performed
// inside TLS calls or data waits; early completion remains queued until a boundary.
class PeerProtocol {
  public:
    explicit PeerProtocol(control::Waiter& peer, std::uint64_t sample) noexcept
        : peer_(peer), sample_(sample) {}
    void synchronize(control::MessageKind kind, std::uint32_t connection,
                     control::Deadline deadline);
    void fail(const std::string& reason, control::Deadline deadline) noexcept;

  private:
    control::Waiter& peer_;
    std::uint64_t sample_;
};

// Preparation only; exchanges identity and shared scenario, never local paths,
// CPU placement or absolute monotonic timestamps.
void negotiate(control::Waiter& peer, model::RunConfig& config, control::Deadline deadline,
               bool readiness = false);
std::string exchange_preparation(control::Waiter& peer, const std::string& local, Role role,
                                 control::Deadline deadline);
void close_all(std::span<int> sockets) noexcept;

} // namespace turtle::lifecycle::detail
