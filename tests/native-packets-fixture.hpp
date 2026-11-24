#pragma once
#include "artifact/json.hpp"
#include <array>
namespace packet_fixture {
using turtle::artifact::Bytes;
inline void append(Bytes &b, std::uint64_t n, unsigned count,
                   bool little = false) {
  for (unsigned i = 0; i < count; ++i)
    b.push_back(
        static_cast<unsigned char>(n >> (8 * (little ? i : count - 1 - i))));
}
inline Bytes packet(bool forward, std::uint32_t seq, unsigned flags,
                    const Bytes &body = {}, std::uint32_t ack = 0,
                    const Bytes &options = {}) {
  Bytes b(12, 0);
  append(b, 0x0800, 2);
  b.push_back(0x45);
  b.push_back(0);
  append(b, 40 + body.size() + options.size(), 2);
  append(b, 0, 4);
  b.push_back(64);
  b.push_back(6);
  append(b, 0, 2);
  std::array<unsigned char, 4> c{192, 0, 2, 2}, s{198, 51, 100, 2};
  auto src = forward ? c : s, dst = forward ? s : c;
  b.insert(b.end(), src.begin(), src.end());
  b.insert(b.end(), dst.begin(), dst.end());
  append(b, forward ? 1234 : 4433, 2);
  append(b, forward ? 4433 : 1234, 2);
  append(b, seq, 4);
  append(b, ack, 4);
  b.push_back(static_cast<unsigned char>((5 + options.size() / 4) << 4));
  b.push_back(static_cast<unsigned char>(flags));
  append(b, 65535, 2);
  append(b, 0, 4);
  b.insert(b.end(), options.begin(), options.end());
  b.insert(b.end(), body.begin(), body.end());
  return b;
}
inline void write_pcap(const std::filesystem::path &file,
                       const std::vector<Bytes> &packets, bool little) {
  Bytes pcap;
  append(pcap, 0xa1b23c4d, 4, little);
  append(pcap, 2, 2, little);
  append(pcap, 4, 2, little);
  append(pcap, 0, 8, little);
  append(pcap, 65535, 4, little);
  append(pcap, 1, 4, little);
  unsigned i = 0;
  for (const auto &p : packets) {
    append(pcap, 2000000000, 4, little);
    append(pcap, 123456789 + i++, 4, little);
    append(pcap, p.size(), 4, little);
    append(pcap, p.size(), 4, little);
    pcap.insert(pcap.end(), p.begin(), p.end());
  }
  turtle::artifact::write_text(file, std::string(pcap.begin(), pcap.end()));
}
} // namespace packet_fixture
