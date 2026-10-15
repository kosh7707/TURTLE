#include "lifecycle/endpoint_protocol.hpp"

#include "lookup/lookup.hpp"

#include <chrono>
#include <stdexcept>
#include <unistd.h>

namespace turtle::lifecycle::detail {

std::uint64_t monotonic_ns(control::Deadline deadline) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(deadline.time_since_epoch()).count();
}

void send(control::Waiter& control, control::MessageKind kind, control::Deadline deadline,
          std::uint64_t sample, std::uint32_t connection, bool hit, std::string address,
          std::uint16_t port, std::uint64_t cleanup_deadline_ns, std::string reason) {
    control::Message message;
    message.kind = kind;
    message.sample = sample;
    message.connection = connection;
    message.request_id = lookup::single_request_id;
    message.cache_hit = hit;
    message.address = std::move(address);
    message.port = port;
    message.cleanup_deadline_monotonic_ns = cleanup_deadline_ns;
    message.reason = std::move(reason);
    control::send_message(control, message, deadline);
}

control::Message ChildProtocol::receive(control::Deadline deadline) {
    auto message = control::receive_message(parent_, deadline);
    if (message.kind == control::MessageKind::AbortFlush) {
        aborted_ = true;
        cleanup_deadline_ = control::Deadline(
            std::chrono::nanoseconds(message.cleanup_deadline_monotonic_ns));
        throw AbortRequested{};
    }
    return message;
}

void ChildProtocol::wait(control::WaitSet& wait_set, bool writing, control::Deadline deadline) {
    if (wait_set.wait(writing, deadline) == control::WaitSet::Ready::Data)
        return;
    (void)receive(deadline);
    throw std::runtime_error("unexpected child control message during data wait");
}

control::Message ChildProtocol::flush(control::Deadline upper_bound) {
    if (aborted_) {
        control::Message message;
        message.kind = control::MessageKind::AbortFlush;
        message.cleanup_deadline_monotonic_ns = monotonic_ns(cleanup_deadline_);
        return message;
    }
    auto message = control::receive_message(parent_, upper_bound);
    if (message.kind == control::MessageKind::AbortFlush ||
        message.kind == control::MessageKind::Flush) {
        cleanup_deadline_ = control::Deadline(
            std::chrono::nanoseconds(message.cleanup_deadline_monotonic_ns));
        aborted_ = message.kind == control::MessageKind::AbortFlush;
        return message;
    }
    throw std::runtime_error("unexpected flush command");
}

void close_all(std::span<int> sockets) noexcept {
    for (int& fd : sockets) {
        if (fd >= 0)
            ::close(fd);
        fd = -1;
    }
}

} // namespace turtle::lifecycle::detail
