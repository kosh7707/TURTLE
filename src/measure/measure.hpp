#pragma once

// Clock, per-thread counters, heap accounting, and calibration only. No files,
// transport, lifecycle policy, or raw-record formatting belongs here.
#include "model/model.hpp"

#include <memory>

namespace turtle::measure {

class Meter {
  public:
    explicit Meter(model::Mode mode, bool request_perf = true);
    ~Meter();
    Meter(const Meter&) = delete;
    Meter& operator=(const Meter&) = delete;
    model::Snapshot read(bool reset_heap_interval = true) noexcept;
    Allocator allocator() noexcept;
    const model::Capabilities& capabilities() const noexcept;
    model::Calibration calibrate(std::size_t repetitions);

  private:
    struct State;
    std::unique_ptr<State> state_;
};

model::ClockPair clock_pair() noexcept;

} // namespace turtle::measure
