#pragma once
#include "model/model.hpp"
#include <cstdint>
namespace turtle::transport {
struct Observation {
    bool sending;
    bool entering;
    const std::uint8_t* data;
    std::size_t requested;
    IoResult result;
    std::uint64_t kernel_realtime_ns = 0;
    bool buffered = false;
    std::uint64_t batch_id = 0;
};
struct TxObservation {
    model::EventKind kind;
    std::uint64_t realtime_ns;
    std::uint32_t byte_id; // last byte in the kernel's timestamp request, modulo 2^32
};
struct Channel {
    int fd = -1;
    void* observer = nullptr; // borrowed; must outlive this Channel and its Io
    void (*observe)(void*, const Observation&) noexcept = nullptr;
    std::span<std::uint8_t> output{};
    bool holding = false;
    bool submit_first_write = false;
    std::size_t direct_remaining = 0;
    std::size_t queued = 0, submitted = 0;
    std::uint64_t batch_id = 0;
    bool tx_timestamps = false;
    int tx_drain_error = 0;
    std::uint64_t tx_acknowledged_end = 0;
    void (*observe_tx)(void*, const TxObservation&) noexcept = nullptr;
    // The returned Io borrows this Channel and fd. A retry keeps the same
    // buffer and operation until progress is reported.
    Io io() noexcept;
    IoResult flush() noexcept;
    void drain_tx() noexcept;
};
// Return observed settings, not requested buffer sizes. Linux may adjust them.
model::SocketSettings configure(int fd, bool nodelay, int send_buffer, int receive_buffer,
                                bool timestamps, bool tx_timestamps = false);
} // namespace turtle::transport
