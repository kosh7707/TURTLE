#pragma once
#include <turtle/implementation.h>
#include <openssl/ssl.h>
#include <string_view>
namespace turtle_openssl {
struct Configuration {
    turtle_role role = TURTLE_CLIENT;
    const char* certificate = nullptr;
    const char* private_key = nullptr;
    const char* trusted_certificate = nullptr;
    const char* peer_name = "localhost";
    const char* groups = "X25519";
};
inline bool parse(Configuration& c, turtle_role role, int argc, const char* const* argv) {
    c.role = role;
    for (int i = 0; i < argc; i += 2) {
        if (i + 1 == argc) return false;
        const std::string_view key(argv[i]);
        if (key == "--cert") c.certificate = argv[i + 1];
        else if (key == "--key") c.private_key = argv[i + 1];
        else if (key == "--ca") c.trusted_certificate = argv[i + 1];
        else if (key == "--peer") c.peer_name = argv[i + 1];
        else if (key == "--groups") c.groups = argv[i + 1];
        else return false;
    }
    return role == TURTLE_SERVER ? c.certificate && c.private_key : c.trusted_certificate != nullptr;
}
bool configure(SSL_CTX*, const Configuration&);
}
