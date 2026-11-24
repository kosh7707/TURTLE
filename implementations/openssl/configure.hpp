#pragma once
#include <turtle/role_types.h>
#include <openssl/ssl.h>
#include <string_view>
#include <cstdlib>
namespace turtle_openssl {
struct Configuration {
    turtle_role role = TURTLE_CLIENT;
    const char* certificate = nullptr;
    const char* private_key = nullptr;
    const char* trusted_certificate = nullptr;
    const char* peer_name = nullptr;
    const char* groups = "X25519";
};
inline bool parse(Configuration& c, turtle_role role, int argc, const char* const* argv) {
    c.role = role;
    auto setting = [](const char* name) {
        const char* value = std::getenv(name);
        return value && *value ? value : nullptr;
    };
    c.certificate = setting("TURTLE_CERT");
    c.private_key = setting("TURTLE_KEY");
    c.trusted_certificate = setting("TURTLE_CA");
    c.peer_name = setting("TURTLE_PEER_NAME");
    if (!c.peer_name) c.peer_name = role == TURTLE_CLIENT ? "localhost" : "client.turtle.test";
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
    // The full-1RTT profile advertises one named group and sends its key
    // share. A list/tuple with a different preferred share could cause HRR
    // and must not silently enter this comparison class.
    const std::string_view group(c.groups);
    if (group.empty() || OPENSSL_strcasecmp(c.groups, "DEFAULT") == 0 ||
        OPENSSL_strcasecmp(c.groups, "DEFAULT_SUITE_B") == 0 || group.find_first_not_of(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") != group.npos)
        return false;
    return *c.peer_name && (c.certificate != nullptr) == (c.private_key != nullptr) &&
           (role == TURTLE_SERVER ? c.certificate != nullptr : c.trusted_certificate != nullptr);
}
bool configure(SSL_CTX*, const Configuration&);
}
