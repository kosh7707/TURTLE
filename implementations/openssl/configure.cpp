#include "configure.hpp"

namespace turtle_openssl {

// 연구자가 바꿀 설정은 이 함수에 둔다. BIO 연결과 계측은 수정하지 않는다.
bool configure(SSL_CTX* context, const Configuration& config) {
    if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_num_tickets(context, 0) != 1 ||
        SSL_CTX_set1_groups_list(context, config.groups) != 1)
        return false;
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);

    if (config.certificate &&
        (SSL_CTX_use_certificate_chain_file(context, config.certificate) != 1 ||
         SSL_CTX_use_PrivateKey_file(context, config.private_key, SSL_FILETYPE_PEM) != 1 ||
         SSL_CTX_check_private_key(context) != 1)) return false;
    if (config.trusted_certificate) {
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER |
            (config.role == TURTLE_SERVER ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), nullptr);
        return SSL_CTX_load_verify_locations(context, config.trusted_certificate, nullptr) == 1;
    }
    return true;
}

} // namespace turtle_openssl
