#pragma once

#include "control/control.hpp"

#include <cstdint>
#include <span>
#include <string>

namespace turtle::lifecycle::detail {

struct AbortRequested final {};

std::uint64_t monotonic_ns(control::Deadline deadline);

void send(control::Waiter& control, control::MessageKind kind, control::Deadline deadline,
          std::uint64_t sample, std::uint32_t connection = 0, bool hit = false,
          std::string address = {}, std::uint16_t port = 0,
          std::uint64_t cleanup_deadline_ns = 0, std::string reason = {});

class ChildProtocol {
  public:
    explicit ChildProtocol(control::Waiter& parent) noexcept : parent_(parent) {}

    control::Message receive(control::Deadline deadline);
    void wait(control::WaitSet& wait_set, bool writing, control::Deadline deadline);
    control::Message flush(control::Deadline upper_bound);

    control::Deadline cleanup_deadline() const noexcept { return cleanup_deadline_; }

  private:
    control::Waiter& parent_;
    bool aborted_ = false;
    control::Deadline cleanup_deadline_{};
};

void close_all(std::span<int> sockets) noexcept;

} // namespace turtle::lifecycle::detail
