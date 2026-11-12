#include "interpret/interpret.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string>
#include <unistd.h>
#include <vector>
namespace {
struct Capture {
    std::string keys;
    std::vector<unsigned> sent_types;
};
void keylog(const SSL* ssl, const char* line) {
    auto* c = static_cast<Capture*>(SSL_get_app_data(ssl));
    c->keys += line;
    c->keys += '\n';
}
void message(int write, int, int type, const void* data, std::size_t size, SSL* ssl, void*) {
    if (write && type == 22 && size)
        static_cast<Capture*>(SSL_get_app_data(ssl))
            ->sent_types.push_back(*static_cast<const unsigned char*>(data));
}
void transfer(SSL* from, SSL* to, std::vector<std::uint8_t>& captured) {
    unsigned char bytes[65536];
    for (;;) {
        const int n = BIO_read(SSL_get_wbio(from), bytes, sizeof(bytes));
        if (n <= 0)
            break;
        captured.insert(captured.end(), bytes, bytes + n);
        // Split each emitted TLS flight, independent of record boundaries.
        for (int p = 0; p < n;) {
            const int chunk = std::min(7, n - p);
            assert(BIO_write(SSL_get_rbio(to), bytes + p, chunk) == chunk);
            p += chunk;
        }
    }
}
} // namespace
int main() {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_EC_gen("prime256v1"),
                                                            EVP_PKEY_free);
    assert(key);
    std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
    assert(cert);
    assert(X509_set_version(cert.get(), 2) == 1);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    assert(X509_set_pubkey(cert.get(), key.get()) == 1);
    X509_NAME* name = X509_get_subject_name(cert.get());
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      reinterpret_cast<const unsigned char*>("localhost"), -1, -1,
                                      0) == 1);
    assert(X509_set_issuer_name(cert.get(), name) == 1);
    assert(X509_sign(cert.get(), key.get(), EVP_sha256()) > 0);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> cc(SSL_CTX_new(TLS_method()), SSL_CTX_free),
        sc(SSL_CTX_new(TLS_method()), SSL_CTX_free);
    for (auto* ctx : {cc.get(), sc.get()}) {
        assert(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1);
        assert(SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1);
        assert(SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") == 1);
        SSL_CTX_set_keylog_callback(ctx, keylog);
        SSL_CTX_set_msg_callback(ctx, message);
        assert(SSL_CTX_set_num_tickets(ctx, 0) == 1);
    }
    assert(SSL_CTX_use_certificate(sc.get(), cert.get()) == 1);
    assert(SSL_CTX_use_PrivateKey(sc.get(), key.get()) == 1);
    assert(X509_STORE_add_cert(SSL_CTX_get_cert_store(cc.get()), cert.get()) == 1);
    SSL_CTX_set_verify(cc.get(), SSL_VERIFY_PEER, nullptr);
    std::unique_ptr<SSL, decltype(&SSL_free)> client(SSL_new(cc.get()), SSL_free),
        server(SSL_new(sc.get()), SSL_free);
    Capture client_capture, server_capture;
    SSL_set_app_data(client.get(), &client_capture);
    SSL_set_app_data(server.get(), &server_capture);
    for (auto* ssl : {client.get(), server.get()}) {
        auto* in = BIO_new(BIO_s_mem());
        auto* out = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(in, -1);
        BIO_set_mem_eof_return(out, -1);
        SSL_set_bio(ssl, in, out);
    }
    SSL_set_connect_state(client.get());
    SSL_set_accept_state(server.get());
    std::vector<std::uint8_t> cs, ss;
    for (int i = 0;
         i < 100 && (!SSL_is_init_finished(client.get()) || !SSL_is_init_finished(server.get()));
         ++i) {
        for (auto* ssl : {client.get(), server.get()}) {
            const int r = SSL_do_handshake(ssl);
            if (r != 1) {
                const int e = SSL_get_error(ssl, r);
                assert(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE);
            }
        }
        transfer(client.get(), server.get(), cs);
        transfer(server.get(), client.get(), ss);
    }
    assert(SSL_is_init_finished(client.get()) && SSL_is_init_finished(server.get()));
    assert(SSL_get_verify_result(client.get()) == X509_V_OK);
    unsigned char payload[]{1, 2, 3, 4}, received[4]{};
    std::size_t size = 0;
    assert(SSL_write_ex(client.get(), payload, 4, &size) == 1 && size == 4);
    transfer(client.get(), server.get(), cs);
    assert(SSL_read_ex(server.get(), received, 4, &size) == 1 && size == 4);
    assert(SSL_write_ex(server.get(), payload, 4, &size) == 1 && size == 4);
    transfer(server.get(), client.get(), ss);
    assert(SSL_read_ex(client.get(), received, 4, &size) == 1 && size == 4);
    const auto decoded = turtle::interpret::decode(cs, ss, client_capture.keys);
    assert(decoded["supported_cipher"] == true && decoded["decryption_complete"] == true);
    for (const auto& [direction, capture] : std::vector<std::pair<std::string, Capture>>{
             {"client_sent", client_capture}, {"server_sent", server_capture}}) {
        std::vector<unsigned> types;
        bool app = false;
        for (const auto& m : decoded[direction]["messages"]) {
            if (m.contains("handshake_type"))
                types.push_back(m["handshake_type"]);
            if (m["name"] == "ApplicationData")
                app = true;
            assert(m["exact_ciphertext_range"] == false);
        }
        assert(types == capture.sent_types && app);
    }
    const auto no_keys = turtle::interpret::decode(cs, ss, "");
    assert(no_keys["decryption_complete"] == false);
    // Unknown handshake split across records stays one message with both envelopes.
    const std::vector<std::uint8_t> unknown{22, 3, 3, 0, 3, 253, 0, 0, 22, 3, 3, 0, 3, 2, 9, 8};
    const auto reassembled = turtle::interpret::decode(unknown, {}, "");
    assert(reassembled["client_sent"]["messages"].size() == 1);
    assert(reassembled["client_sent"]["messages"][0]["name"] == "UnknownHandshake");
    assert(reassembled["client_sent"]["messages"][0]["records"].size() == 2);
    const auto dir = std::filesystem::temp_directory_path() /
                     ("turtle-interpret-native-" + std::to_string(getpid()));
    std::filesystem::create_directory(dir);
    auto check_unavailable = [&](const char* name, nlohmann::json header,
                                 const char* expected_reason) {
        const auto raw = dir / (std::string(name) + ".jsonl");
        const auto out = dir / (std::string(name) + ".decoded.json");
        std::ofstream(raw) << header.dump() << '\n';
        const auto result = turtle::interpret::analyze(raw, out);
        const auto& connection = result["connections"][0];
        assert(connection["decryption_complete"] == false);
        assert(connection["availability"]["tls_stream"]["available"] == false);
        assert(connection["availability"]["tls_stream"]["reason"] == expected_reason);
        assert(connection["client_sent"]["decryption_complete"] == false);
    };
    nlohmann::json native = {
        {"schema", 3},
        {"measurement_contract_revision", 3},
        {"run_id", "decode-fixture"},
        {"context_id", "context"},
        {"type", "sample"},
        {"sample", 1},
        {"role", "client"},
        {"connections", nlohmann::json::array({{{"index", 0}}})},
        {"availability",
         {{"tls_stream", {{"available", false}, {"reason", "native_socket_io_not_observed"}}}}}};
    check_unavailable("client", native, "native_socket_io_not_observed");
    auto observer_off = native;
    observer_off["availability"]["tls_stream"]["reason"] = "channel_observer_disabled";
    observer_off["observation_level"] = "observer-disabled";
    observer_off["config"] = {{"channel_observer", false}, {"tls", {{"framework_io", true}}}};
    check_unavailable("observer-off", observer_off, "channel_observer_disabled");
    for (int schema : {1, 2}) {
        auto old = native;
        old["schema"] = schema;
        const auto raw = dir / "unsupported.jsonl";
        std::ofstream(raw) << old.dump() << '\n';
        bool rejected = false;
        try {
            turtle::interpret::analyze(raw, dir / "unsupported.decoded.json");
        } catch (const std::runtime_error& error) {
            rejected = std::string(error.what()).find("requires schema 3") != std::string::npos;
        }
        assert(rejected);
    }
    std::filesystem::remove_all(dir);
    std::cout << "real TLS 1.3 decryption and callback comparison passed\n";
}
