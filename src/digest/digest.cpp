#include "digest.hpp"
#include <array>
#include <bit>
namespace turtle {
std::string sha256(std::span<const std::uint8_t> data) {
    constexpr std::array<std::uint32_t, 64> k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    std::array<std::uint32_t, 8> hash = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    auto total = ((data.size() + 9 + 63) / 64) * 64;
    for (std::size_t off = 0; off < total; off += 64) {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0; i < 64; ++i) {
            auto p = off + i;
            std::uint8_t b = 0;
            if (p < data.size())
                b = data[p];
            else if (p == data.size())
                b = 128;
            else if (p >= total - 8)
                b = std::uint8_t((std::uint64_t(data.size()) * 8) >> (8 * (total - 1 - p)));
            w[i / 4] |= std::uint32_t(b) << (24 - 8 * (i % 4));
        }
        for (unsigned i = 16; i < 64; ++i) {
            auto x = w[i - 15], y = w[i - 2];
            w[i] = w[i - 16] + (std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3)) + w[i - 7] +
                   (std::rotr(y, 17) ^ std::rotr(y, 19) ^ (y >> 10));
        }
        auto a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5],
             g = hash[6], h = hash[7];
        for (unsigned i = 0; i < 64; ++i) {
            auto t1 = h + (std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25)) +
                      ((e & f) ^ (~e & g)) + k[i] + w[i];
            auto t2 = (std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22)) +
                      ((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string result(64, '0');
    for (unsigned i = 0; i < 8; ++i)
        for (unsigned j = 0; j < 8; ++j)
            result[i * 8 + j] = digits[(hash[i] >> (28 - j * 4)) & 15];
    return result;
}
} // namespace turtle
