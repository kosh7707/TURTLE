// 구현체 교체 사용 경로를 확인하기 위한 정상 TLS 설정 예제다.
#include "configure.hpp"

namespace turtle_openssl {

bool configure(SSL_CTX* context, const Configuration& config) {
    if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set1_groups_list(context, "X25519") != 1 ||
        SSL_CTX_set_num_tickets(context, 0) != 1)
        return false;
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    if (config.role == TURTLE_SERVER) {
        return SSL_CTX_use_certificate_chain_file(context, config.certificate) == 1 &&
               SSL_CTX_use_PrivateKey_file(context, config.private_key, SSL_FILETYPE_PEM) == 1;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nullptr);
    return SSL_CTX_load_verify_locations(context, config.trusted_certificate, nullptr) == 1;
}

} // namespace turtle_openssl
