#include "configure.hpp"
#include <string_view>
namespace turtle_wolfssl {
bool parse(Configuration& c, turtle_role role, int argc, const char* const* argv) {
    c.role = role;
    for (int i = 0; i < argc; i += 2) {
        if (i + 1 == argc) return false;
        const std::string_view key(argv[i]), value(argv[i + 1]);
        if (key == "--cert") c.certificate = argv[i + 1];
        else if (key == "--key") c.private_key = argv[i + 1];
        else if (key == "--ca") c.trusted_certificate = argv[i + 1];
        else if (key == "--peer") c.peer_name = argv[i + 1];
        else if (key == "--groups") {
            if (value == "X25519") c.group = WOLFSSL_ECC_X25519;
            else if (value == "MLKEM768") c.group = WOLFSSL_ML_KEM_768;
            else if (value == "X25519MLKEM768") c.group = WOLFSSL_X25519MLKEM768;
            else return false;
        } else return false;
    }
    return (c.certificate != nullptr) == (c.private_key != nullptr) &&
           (role == TURTLE_SERVER ? c.certificate != nullptr : c.trusted_certificate != nullptr);
}
bool configure(WOLFSSL_CTX* context, const Configuration& c) {
    int group = c.group;
    if (wolfSSL_CTX_set_groups(context, &group, 1) != WOLFSSL_SUCCESS) return false;
    wolfSSL_CTX_set_session_cache_mode(context, WOLFSSL_SESS_CACHE_OFF);
    if (c.role == TURTLE_SERVER && wolfSSL_CTX_no_ticket_TLSv13(context) != 0) return false;
    if (c.certificate &&
        (wolfSSL_CTX_use_certificate_chain_file(context, c.certificate) != WOLFSSL_SUCCESS ||
         wolfSSL_CTX_use_PrivateKey_file(context, c.private_key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS))
        return false;
    if (c.trusted_certificate) {
        wolfSSL_CTX_set_verify(context, WOLFSSL_VERIFY_PEER |
            (c.role == TURTLE_SERVER ? WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), nullptr);
        return wolfSSL_CTX_load_verify_locations(context, c.trusted_certificate, nullptr) == WOLFSSL_SUCCESS;
    }
    return true;
}
}
