#include "adapter.hpp"
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace turtle::openssl_adapter {
State::~State() { SSL_CTX_free(ssl); BIO_meth_free(method); }
Session::~Session() { SSL_free(ssl); }
namespace {
void require(bool ok, const char* what) { if (!ok) throw std::runtime_error(what); }
int bio_create(BIO* bio) { BIO_set_init(bio, 1); return 1; }
int bio_destroy(BIO*) { return 1; }
long bio_control(BIO*, int command, long, void*) { return command == BIO_CTRL_FLUSH ? 1 : 0; }
int transfer(BIO* bio, char* data, int size, bool send) {
    auto& s = *static_cast<Session*>(BIO_get_data(bio));
    BIO_clear_retry_flags(bio);
    if (size <= 0) return 0;
    auto r = send ? s.io.send(s.io.context, reinterpret_cast<const std::uint8_t*>(data), size)
                  : s.io.recv(s.io.context, reinterpret_cast<std::uint8_t*>(data), size);
    if (r.status == IoStatus::Ok) return static_cast<int>(r.bytes);
    if (r.status == IoStatus::Closed) return 0;
    if (r.status == IoStatus::WantRead) BIO_set_retry_read(bio);
    if (r.status == IoStatus::WantWrite) BIO_set_retry_write(bio);
    return -1;
}
int bio_read(BIO* bio, char* out, int size) { return transfer(bio, out, size, false); }
int bio_write(BIO* bio, const char* in, int size) { return transfer(bio, const_cast<char*>(in), size, true); }
void keylog(const SSL* ssl, const char* line) {
    auto& s = *static_cast<Session*>(SSL_get_app_data(ssl));
    auto sink = s.state.services.key_log;
    if (sink.append && !sink.append(sink.context, line, std::strlen(line))) s.sink_failed = true;
}
void message(int outgoing, int, int type, const void* bytes, std::size_t size, SSL* ssl, void*) {
    auto* session = static_cast<Session*>(SSL_get_app_data(ssl));
    if (!session) return;
    const auto* data = static_cast<const std::uint8_t*>(bytes);
    constexpr std::uint8_t random[] = {
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    if (type == SSL3_RT_HANDSHAKE && size >= 38 && data[0] == SSL3_MT_SERVER_HELLO &&
        std::memcmp(data + 6, random, 32) == 0) session->hrr = true;
    auto sink = session->state.services.plaintext;
    if (session->state.services.trace_mode && sink.append && type <= 255 &&
        !sink.append(sink.context, outgoing != 0, type, data, size)) session->sink_failed = true;
}
Step result(Session& s, int rc) {
    if (s.sink_failed) {
        std::strcpy(s.error.data(), "capture sink exhausted");
        return Step::Failed;
    }
    if (rc > 0) return Step::Done;
    const int error = SSL_get_error(s.ssl, rc);
    if (error == SSL_ERROR_WANT_READ) return Step::WantRead;
    if (error == SSL_ERROR_WANT_WRITE) return Step::WantWrite;
    const auto code = ERR_peek_last_error();
    if (code) ERR_error_string_n(code, s.error.data(), s.error.size());
    else std::strcpy(s.error.data(), "TLS operation failed or peer closed");
    return Step::Failed;
}
Context* setup(Role role, const TlsConfig& config, const HostServices& services,
               std::span<const std::uint8_t> saved) {
    require(saved.empty(), "OpenSSL adapter has no serializable context");
    require(config.record_size_limit == 0 && !config.certificate_compression,
            "OpenSSL adapter does not implement requested record limit or certificate compression");
    auto s = std::make_unique<State>(role, config, services);
    s->ssl = SSL_CTX_new(TLS_method());
    require(s->ssl, "SSL_CTX_new failed");
    require(SSL_CTX_set_min_proto_version(s->ssl, TLS1_3_VERSION) == 1 &&
            SSL_CTX_set_max_proto_version(s->ssl, TLS1_3_VERSION) == 1, "TLS1.3 configuration failed");
    require(SSL_CTX_set_ciphersuites(s->ssl, config.cipher.c_str()) == 1, "cipher unsupported");
    const char* group = config.group == "secp256r1" ? "P-256" : config.group.c_str();
    require(SSL_CTX_set1_groups_list(s->ssl, group) == 1, "group unsupported");
    require(SSL_CTX_set1_sigalgs_list(s->ssl, config.signature.c_str()) == 1, "signature unsupported");
    SSL_CTX_set_session_cache_mode(s->ssl, SSL_SESS_CACHE_OFF);
    require(SSL_CTX_set_num_tickets(s->ssl, config.tickets) == 1, "ticket configuration failed");
    SSL_CTX_set_max_early_data(s->ssl, 0);
    if (config.compatibility_ccs) SSL_CTX_set_options(s->ssl, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
    else SSL_CTX_clear_options(s->ssl, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
    require(SSL_CTX_load_verify_locations(s->ssl, config.ca_file.c_str(), nullptr) == 1, "CA load failed");
    int verify = SSL_VERIFY_NONE;
    if (role == Role::Client || config.mutual_auth) verify = SSL_VERIFY_PEER;
    if (role == Role::Server && config.mutual_auth) verify |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_CTX_set_verify(s->ssl, verify, nullptr);
    if (role == Role::Server || config.mutual_auth) {
        const auto& cert = role == Role::Server ? config.server_certificate : config.client_certificate;
        const auto& key = role == Role::Server ? config.server_key : config.client_key;
        require(SSL_CTX_use_certificate_chain_file(s->ssl, cert.c_str()) == 1, "certificate load failed");
        require(SSL_CTX_use_PrivateKey_file(s->ssl, key.c_str(), SSL_FILETYPE_PEM) == 1 &&
                SSL_CTX_check_private_key(s->ssl) == 1, "private key load failed");
    }
    SSL_CTX_set_keylog_callback(s->ssl, keylog);
    SSL_CTX_set_msg_callback(s->ssl, message);
    s->method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "TURTLE borrowed transport");
    require(s->method && BIO_meth_set_create(s->method, bio_create) &&
            BIO_meth_set_destroy(s->method, bio_destroy) && BIO_meth_set_ctrl(s->method, bio_control) &&
            BIO_meth_set_read(s->method, bio_read) && BIO_meth_set_write(s->method, bio_write),
            "BIO method setup failed");
    // Initialize random providers before the runtime applies file restrictions.
    unsigned char seed;
    require(RAND_bytes(&seed, 1) == 1, "random initialization failed");
    return s.release();
}
Connection* open(Context* context, const Io& io) {
    auto& state = *static_cast<State*>(context);
    auto s = std::make_unique<Session>(state, io);
    s->ssl = SSL_new(state.ssl);
    require(s->ssl, "SSL_new failed");
    SSL_set_app_data(s->ssl, s.get());
    if (state.config.framework_io) {
        require(io.send && io.recv, "transport callbacks missing");
        BIO* bio = BIO_new(state.method);
        require(bio, "BIO_new failed");
        BIO_set_data(bio, s.get());
        SSL_set_bio(s->ssl, bio, bio);
    } else require(SSL_set_fd(s->ssl, io.native_socket) == 1, "native socket setup failed");
    if (state.role == Role::Client) {
        SSL_set_connect_state(s->ssl);
        require(SSL_set_tlsext_host_name(s->ssl, state.config.server_name.c_str()) == 1 &&
                SSL_set1_host(s->ssl, state.config.server_name.c_str()) == 1, "hostname configuration failed");
    } else SSL_set_accept_state(s->ssl);
    return s.release();
}
Declaration declaration(const Context* context) {
    const auto& s = *static_cast<const State*>(context);
    Declaration d;
    d.library = "OpenSSL"; d.version = OpenSSL_version(OPENSSL_VERSION);
    d.build_options = OpenSSL_version(OPENSSL_CFLAGS);
    d.callback_io = s.config.framework_io; d.key_log = true; d.plaintext_hook = true;
    d.context_description = "No resumption state retained; save returns empty bytes";
    d.memory_note = "TLS allocator hooks not installed; TLS heap is unobserved";
    return d;
}
Negotiated negotiated(Connection* connection) {
    auto& s = *static_cast<Session*>(connection);
    Negotiated n;
    n.version = SSL_get_version(s.ssl); n.cipher = SSL_get_cipher_name(s.ssl);
    int group = SSL_get_negotiated_group(s.ssl);
    if (group == NID_X9_62_prime256v1) n.group = "secp256r1";
    else if (group == NID_X25519) n.group = "x25519";
    else if (group) { const char* name = SSL_group_to_name(s.ssl, group); if (name) n.group = name; }
    n.resumed = SSL_session_reused(s.ssl) != 0; n.hello_retry_request = s.hrr;
    n.peer_certificate_present = SSL_get0_peer_certificate(s.ssl) != nullptr;
    return n;
}
Verification verification(Connection* connection) {
    auto& s = *static_cast<Session*>(connection);
    if (!SSL_is_init_finished(s.ssl)) return Verification::Failed;
    if (s.state.role == Role::Server && !s.state.config.mutual_auth &&
        !SSL_get0_peer_certificate(s.ssl)) return Verification::NotApplicable;
    return SSL_get0_peer_certificate(s.ssl) && SSL_get_verify_result(s.ssl) == X509_V_OK
           ? Verification::Passed : Verification::Failed;
}
}
} // namespace turtle::openssl_adapter

extern "C" turtle::ImplementationApi turtle_adapter_v1() {
    using namespace turtle;
    using namespace turtle::openssl_adapter;
    return {adapter_api_version, []() noexcept { return "openssl"; }, declaration, setup, open,
        [](Connection* c) { auto& s = *static_cast<Session*>(c); ERR_clear_error(); return result(s, SSL_do_handshake(s.ssl)); },
        verification, negotiated,
        [](Connection* c, const std::uint8_t* p, std::size_t n) { auto& s = *static_cast<Session*>(c); std::size_t bytes = 0; ERR_clear_error(); int rc = SSL_write_ex(s.ssl, p, n, &bytes); return AppResult{result(s, rc), bytes}; },
        [](Connection* c, std::uint8_t* p, std::size_t n) { auto& s = *static_cast<Session*>(c); std::size_t bytes = 0; ERR_clear_error(); int rc = SSL_read_ex(s.ssl, p, n, &bytes); return AppResult{result(s, rc), bytes}; },
        [](const Connection* c) noexcept { return static_cast<const Session*>(c)->error.data(); },
        [](Connection* c) noexcept { delete c; },
        [](Context*) { return std::vector<std::uint8_t>{}; },
        [](Context* c) noexcept { delete c; }};
}
