#pragma once

// Fixed-capacity TLS capture during measurement; serialization follows it.
#include "model/model.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace turtle::model {
struct SampleInfo;
}

namespace turtle::record {

struct Limits {
    std::size_t events = 32768;
    std::size_t bytes_per_stream = 1024 * 1024;
    std::size_t keylog_bytes = 256 * 1024;
    std::size_t connections = 1;
};

struct PlaintextMessage {
    std::size_t connection = 0;
    bool outgoing = false;
    unsigned content_type = 0;
    std::size_t offset = 0;
    std::size_t length = 0;
};

class Buffer {
  public:
    explicit Buffer(const Limits& limits);
    ~Buffer();
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    // Reserves a stable slot from the fixed event storage. The caller may
    // finish fields after other capture work without allocating or changing
    // event order. A null result records an overflow exactly like append().
    model::Event* prepare_event(model::Event event) noexcept;
    bool append(const model::Event& event) noexcept;
    bool append_bytes(std::size_t connection, model::Direction direction,
                      std::span<const std::uint8_t> bytes) noexcept;
    bool append_keylog(std::string_view line) noexcept;
    bool append_plaintext(std::size_t connection, bool outgoing, unsigned type,
                          std::span<const std::uint8_t> bytes) noexcept;
    std::span<const model::Event> events() const noexcept;
    std::span<const std::uint8_t> bytes(std::size_t connection,
                                        model::Direction direction) const noexcept;
    std::string_view keylog() const noexcept;
    std::span<const PlaintextMessage> plaintext_messages() const noexcept;
    std::span<const std::uint8_t> plaintext_bytes() const noexcept;
    bool overflowed() const noexcept;
    std::size_t dropped() const noexcept;

  private:
    struct State;
    std::unique_ptr<State> state_;
};

// Open every artifact before resource limits are applied. Each role writes its
// own files after measurement, avoiding large IPC transfers while the parent waits.
class Writer {
  public:
    Writer(const std::string& sample_directory, Role role, std::size_t connections);
    ~Writer();
    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;
    void write(const model::SampleInfo& info, const Buffer& buffer);
    void write_context(std::span<const std::uint8_t> saved);

  private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace turtle::record
