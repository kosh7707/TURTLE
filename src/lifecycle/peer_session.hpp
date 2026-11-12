#pragma once

#include "control/control.hpp"
#include "model/preparation.hpp"
#include "model/run_config.hpp"

namespace turtle::model {
struct SampleInfo;
}

namespace turtle::lifecycle::detail {

// Owns the listeners and one peer TCP session from connection through cleanup.
// Readiness uses this same session and never opens a preliminary TLS connection.
class PeerSession {
  public:
    PeerSession(model::RunConfig& config, control::Deadline deadline);
    ~PeerSession();
    PeerSession(const PeerSession&) = delete;
    PeerSession& operator=(const PeerSession&) = delete;
    void connect();
    void prepare(const model::SampleInfo& info, control::Waiter& peer);
    int listener() const noexcept {
        return listener_;
    }
    int peer() const noexcept {
        return peer_;
    }
    const model::PreparationInfo& status() const noexcept {
        return status_;
    }

  private:
    model::RunConfig& config_;
    control::Deadline deadline_;
    model::PreparationInfo status_;
    int listener_ = -1;
    int control_listener_ = -1;
    int peer_ = -1;
};

} // namespace turtle::lifecycle::detail
