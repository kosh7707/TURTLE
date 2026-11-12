#pragma once

#include <array>
#include <cstring>
#include <turtle/adapter.hpp>

namespace turtle::adapter_detail {
// Connection-owned forwarding only. Patched C libraries supply the actual
// work boundaries; ordinary public message notifications never enter here.
struct TraceForwarder {
    TraceSink sink{};
    bool enabled = false;
    bool failed = false;
    std::array<std::uint64_t, 12> record_ids{};
    void emit(int operation, int end, int type, int result) noexcept {
        if (!enabled || !sink.append)
            return;
        if (operation < 0 || static_cast<std::size_t>(operation) >= record_ids.size()) {
            failed = true;
            return;
        }
        const auto op = static_cast<TraceOperation>(operation);
        const auto index = static_cast<std::size_t>(operation);
        std::uint64_t id;
        if (operation == 2 || operation == 3 || operation >= 6) {
            if (!end)
                ++record_ids[index];
            id = (static_cast<std::uint64_t>(operation + 1) << 32) | record_ids[index];
        } else {
            id = (static_cast<std::uint64_t>(operation + 1) << 32) | static_cast<unsigned>(type);
        }
        if (!sink.append(sink.context, {op, end ? TracePhase::End : TracePhase::Begin, id,
                                        static_cast<unsigned>(type), result}))
            failed = true;
    }
    void message(int version, int type, const void* bytes, std::size_t size) noexcept {
        if (version != 0x5455)
            return;
        int result = 0;
        if (bytes && size == sizeof(result))
            std::memcpy(&result, bytes, size);
        emit(type >> 16, (type >> 8) & 1, type & 255, result);
    }
};
} // namespace turtle::adapter_detail
