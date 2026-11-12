#include <array>
#include <cassert>
#include <cstdio>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

namespace {
std::vector<byte> input() {
    std::string hex;
    std::cin >> hex;
    assert(hex.size() % 2 == 0);
    std::vector<byte> bytes;
    for (std::size_t i = 0; i < hex.size(); i += 2)
        bytes.push_back(static_cast<byte>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return bytes;
}
void output(std::span<const byte> bytes) {
    for (byte value : bytes)
        std::printf("%02x", static_cast<unsigned>(value));
    std::puts("");
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    MlKemKey key{};
    assert(wc_MlKemKey_Init(&key, WC_ML_KEM_768, nullptr, INVALID_DEVID) == 0);
    const auto seed = input();
    std::array<byte, WC_ML_KEM_768_PUBLIC_KEY_SIZE> pub{};
    std::array<byte, WC_ML_KEM_768_PRIVATE_KEY_SIZE> priv{};
    std::array<byte, WC_ML_KEM_768_CIPHER_TEXT_SIZE> ct{};
    std::array<byte, WC_ML_KEM_SS_SZ> secret{}, recovered{};
    if (std::string(argv[1]) == "keygen-roundtrip") {
        assert(seed.size() == WC_ML_KEM_MAKEKEY_RAND_SZ);
        assert(wc_MlKemKey_MakeKeyWithRandom(&key, seed.data(), seed.size()) == 0);
        assert(wc_MlKemKey_EncodePublicKey(&key, pub.data(), pub.size()) == 0);
        assert(wc_MlKemKey_EncodePrivateKey(&key, priv.data(), priv.size()) == 0);
        output(pub);
        output(priv);
        const auto coins = input();
        assert(coins.size() == WC_ML_KEM_ENC_RAND_SZ);
        assert(wc_MlKemKey_EncapsulateWithRandom(&key, ct.data(), secret.data(), coins.data(),
                                                 coins.size()) == 0);
        assert(wc_MlKemKey_Decapsulate(&key, recovered.data(), ct.data(), ct.size()) == 0);
        assert(secret == recovered);
        output(ct);
        output(secret);
    } else {
        assert(std::string(argv[1]) == "encapsulate");
        assert(seed.size() == WC_ML_KEM_ENC_RAND_SZ);
        const auto encoded = input();
        assert(wc_MlKemKey_DecodePublicKey(&key, encoded.data(), encoded.size()) == 0);
        assert(wc_MlKemKey_EncapsulateWithRandom(&key, ct.data(), secret.data(), seed.data(),
                                                 seed.size()) == 0);
        output(ct);
        output(secret);
    }
    wc_MlKemKey_Free(&key);
}
