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
};
struct Channel {
    int fd = -1;
    void* observer = nullptr;
    void (*observe)(void*, const Observation&) noexcept = nullptr;
    Io io() noexcept;
};
// Return observed settings, not requested buffer sizes. Linux may adjust them.
model::SocketSettings configure(int fd, bool nodelay, int send_buffer, int receive_buffer,
                                bool timestamps);
} // namespace turtle::transport
