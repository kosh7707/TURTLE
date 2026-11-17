#pragma once
#include <turtle/implementation.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
namespace turtle_wolfssl {
struct Configuration {
    turtle_role role = TURTLE_CLIENT;
    const char* certificate = nullptr;
    const char* private_key = nullptr;
    const char* trusted_certificate = nullptr;
    const char* peer_name = "localhost";
    int group = WOLFSSL_ECC_X25519;
};
bool parse(Configuration&, turtle_role, int, const char* const*);
bool configure(WOLFSSL_CTX*, const Configuration&);
}
