#pragma once
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
namespace turtle::native::detail {
inline constexpr auto start_wait_limit = std::chrono::seconds(15);
// Local IPC, explicit byte order. The optional stamp is CLOCK_MONOTONIC in
// the sender's namespace. The release token binds a reply to THIS release.
using StartPacket = std::array<unsigned char, 17>;
inline StartPacket start_packet(char opcode, std::uint64_t ns,
                                std::uint64_t token = 0) {
  StartPacket p{};
  p[0] = static_cast<unsigned char>(opcode);
  for (int i = 8; i > 0; --i) {
    p[i] = static_cast<unsigned char>(ns);
    ns >>= 8;
    p[i + 8] = static_cast<unsigned char>(token);
    token >>= 8;
  }
  return p;
}
inline std::uint64_t start_word(const StartPacket &p, size_t first) {
  std::uint64_t v = 0;
  for (size_t i = first; i < first + 8; ++i)
    v = (v << 8) | p[i];
  return v;
}
inline std::uint64_t start_stamp(const StartPacket &p) {
  return start_word(p, 1);
}
inline std::uint64_t start_token(const StartPacket &p) {
  return start_word(p, 9);
}
} // namespace turtle::native::detail
