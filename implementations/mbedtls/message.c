#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "boundary.h"
#include "ssl_tls13_invasive.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <turtle/implementation.h>

struct turtle_context {
    turtle_options options;
    mbedtls_ssl_config config;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
    mbedtls_x509_crt ca, certificate;
    mbedtls_pk_context key;
    int suites[2];
    uint16_t groups[2], signatures[2];
};
struct turtle_connection {
    size_t received;
    turtle_context* owner;
    mbedtls_ssl_context ssl;
    unsigned char* message;
    size_t message_size;
    int complete;
    char error[256];
};
static int checked(turtle_connection* c, int rc) {
    if (rc) {
        mbedtls_strerror(rc, c->error, sizeof(c->error));
        return 0;
    }
    return 1;
}
static turtle_progress progress(int ok, size_t consumed, size_t produced) {
    turtle_progress p = {ok ? TURTLE_DONE : TURTLE_ERROR, consumed, produced, ok ? 0 : -1};
    return p;
}
static turtle_support support(void) {
    turtle_support s = {"mbedtls", MBEDTLS_VERSION_STRING_FULL, "standard-tls13"};
    return s;
}
static void destroy_context(turtle_context* c) {
    mbedtls_ssl_config_free(&c->config);
    mbedtls_x509_crt_free(&c->ca);
    mbedtls_x509_crt_free(&c->certificate);
    mbedtls_pk_free(&c->key);
    mbedtls_ctr_drbg_free(&c->rng);
    mbedtls_entropy_free(&c->entropy);
    free(c);
}
static turtle_context* create_context(const turtle_options* o, char* error, size_t n) {
    turtle_context* c = calloc(1, sizeof(*c));
    int rc = 0;
    if (!c)
        return NULL;
    c->options = *o;
    mbedtls_ssl_config_init(&c->config);
    mbedtls_entropy_init(&c->entropy);
    mbedtls_ctr_drbg_init(&c->rng);
    mbedtls_x509_crt_init(&c->ca);
    mbedtls_x509_crt_init(&c->certificate);
    mbedtls_pk_init(&c->key);
#define TRY(call)                                                                                  \
    if ((rc = (call)) != 0)                                                                        \
    goto fail
    TRY(psa_crypto_init());
    TRY(mbedtls_ctr_drbg_seed(&c->rng, mbedtls_entropy_func, &c->entropy,
                              (const unsigned char*)"TURTLE", 6));
    TRY(mbedtls_ssl_config_defaults(
        &c->config, o->role == TURTLE_CLIENT ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    mbedtls_ssl_conf_min_tls_version(&c->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&c->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_tls13_key_exchange_modes(&c->config,
                                              MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
    mbedtls_ssl_conf_rng(&c->config, mbedtls_ctr_drbg_random, &c->rng);
    mbedtls_ssl_conf_authmode(&c->config, o->role == TURTLE_CLIENT || o->mutual_auth
                                              ? MBEDTLS_SSL_VERIFY_REQUIRED
                                              : MBEDTLS_SSL_VERIFY_NONE);
    c->suites[0] = MBEDTLS_TLS1_3_AES_128_GCM_SHA256;
    c->groups[0] = MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1;
    c->signatures[0] = MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256;
    if (strcmp(o->group, "P-256") && strcmp(o->group, "secp256r1")) {
        rc = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        goto fail;
    }
    mbedtls_ssl_conf_ciphersuites(&c->config, c->suites);
    mbedtls_ssl_conf_groups(&c->config, c->groups);
    mbedtls_ssl_conf_sig_algs(&c->config, c->signatures);
    mbedtls_ssl_conf_session_tickets(&c->config, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    mbedtls_ssl_conf_new_session_tickets(&c->config, 0);
    if (o->role == TURTLE_CLIENT || o->mutual_auth) {
        TRY(mbedtls_x509_crt_parse_file(&c->ca, o->ca_file));
        mbedtls_ssl_conf_ca_chain(&c->config, &c->ca, NULL);
    }
    if (o->role == TURTLE_SERVER || o->mutual_auth) {
        TRY(mbedtls_x509_crt_parse_file(&c->certificate, o->certificate_file));
        TRY(mbedtls_pk_parse_keyfile(&c->key, o->private_key_file, NULL, mbedtls_ctr_drbg_random,
                                     &c->rng));
        TRY(mbedtls_ssl_conf_own_cert(&c->config, &c->certificate, &c->key));
    }
    return c;
fail:
    mbedtls_strerror(rc, error, n);
    destroy_context(c);
    return NULL;
#undef TRY
}
static void destroy_connection(turtle_connection* c) {
    mbedtls_ssl_free(&c->ssl);
    free(c->message);
    free(c);
}
static turtle_connection* create_connection(turtle_context* owner, char* error, size_t n) {
    turtle_connection* c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->owner = owner;
    mbedtls_ssl_init(&c->ssl);
    c->message = malloc(owner->options.max_message);
    int rc = mbedtls_ssl_setup(&c->ssl, &owner->config);
    if (!rc && owner->options.role == TURTLE_CLIENT)
        rc = mbedtls_ssl_set_hostname(&c->ssl, owner->options.server_name);
    if (rc || !c->message) {
        mbedtls_strerror(rc, error, n);
        destroy_connection(c);
        return NULL;
    }
    return c;
}
static int transition(turtle_connection* c, turtle_transition op, unsigned type, turtle_bytes msg) {
    mbedtls_ssl_context* s = &c->ssl;
    int rc = 0;
    int server = c->owner->options.role == TURTLE_SERVER;
    switch (op) {
    case TURTLE_BEGIN:
        s->tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
        s->state = server ? MBEDTLS_SSL_CLIENT_HELLO : MBEDTLS_SSL_HELLO_REQUEST;
        break;
    case TURTLE_PREPARE_SEND:
        if (type == 20)
            rc = ssl_tls13_prepare_finished_message(s);
        if (type == 1)
            rc = ssl_prepare_client_hello(s);
        if (type == 2)
            rc = ssl_tls13_prepare_server_hello(s);
        if (type == 13)
            s->handshake->certificate_request_sent = 1;
        break;
    case TURTLE_COMMIT_SEND:
    case TURTLE_COMMIT_RECEIVE:
        rc = mbedtls_ssl_add_hs_msg_to_checksum(s, type, msg.data + 4, msg.size - 4);
        if (rc)
            break;
        if (type == 1) {
            rc = server ? ssl_tls13_postprocess_client_hello(s, 0)
                        : mbedtls_ssl_tls13_finalize_client_hello(s);
        }
        if (type == 2) {
            rc =
                server ? ssl_tls13_finalize_server_hello(s) : ssl_tls13_postprocess_server_hello(s);
            if (!rc) {
                mbedtls_ssl_set_outbound_transform(s, s->handshake->transform_handshake);
                mbedtls_ssl_set_inbound_transform(s, s->handshake->transform_handshake);
            }
        }
        if (type == 11 && op == TURTLE_COMMIT_RECEIVE)
            rc = ssl_tls13_validate_certificate(s);
        if (type == 20) {
            int server_finished =
                (server && op == TURTLE_COMMIT_SEND) || (!server && op == TURTLE_COMMIT_RECEIVE);
            if (server_finished) {
                rc = mbedtls_ssl_tls13_compute_application_transform(s);
                if (!rc) {
                    if (server)
                        mbedtls_ssl_set_outbound_transform(s, s->transform_application);
                    else
                        mbedtls_ssl_set_inbound_transform(s, s->transform_application);
                }
            } else {
                rc = mbedtls_ssl_tls13_compute_resumption_master_secret(s);
                if (!rc) {
                    if (server)
                        mbedtls_ssl_set_inbound_transform(s, s->transform_application);
                    else
                        mbedtls_ssl_set_outbound_transform(s, s->transform_application);
                }
            }
        }
        break;
    case TURTLE_PREPARE_RECEIVE:
        c->received = 0;
        if (type == 2) {
            s->session_negotiate->tls_version = s->tls_version;
            s->session_negotiate->endpoint = s->conf->endpoint;
        }
        if (type == 20)
            rc = ssl_tls13_preprocess_finished_message(s);
        break;
    case TURTLE_FINISH:
        /* Keys were switched explicitly above; preserve application sequence numbers. */
        s->session = s->session_negotiate;
        s->session_negotiate = NULL;
        s->state = MBEDTLS_SSL_HANDSHAKE_OVER;
        c->complete = 1;
        break;
    }
    return checked(c, rc);
}
static turtle_progress assemble(turtle_connection* c, unsigned type, size_t offset,
                                turtle_buffer out) {
    if (!offset) {
        mbedtls_ssl_context* s = &c->ssl;
        unsigned char *b = c->message + 4, *end = c->message + c->owner->options.max_message;
        size_t n = 0, binders = 0;
        int rc = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        switch (type) {
        case 1:
            rc = ssl_write_client_hello_body(s, b, end, &n, &binders);
            break;
        case 2:
            rc = ssl_tls13_write_server_hello_body(s, b, end, &n, 0);
            break;
        case 8:
            rc = ssl_tls13_write_encrypted_extensions_body(s, b, end, &n);
            break;
        case 13:
            rc = ssl_tls13_write_certificate_request_body(s, b, end, &n);
            break;
        case 11:
            rc = ssl_tls13_write_certificate_body(s, b, end, &n);
            break;
        case 15:
            rc = ssl_tls13_write_certificate_verify_body(s, b, end, &n);
            break;
        case 20:
            rc = ssl_tls13_write_finished_message_body(s, b, end, &n);
            break;
        }
        if (!checked(c, rc) || binders)
            return progress(0, 0, 0);
        c->message[0] = type;
        c->message[1] = (n >> 16) & 255;
        c->message[2] = (n >> 8) & 255;
        c->message[3] = n & 255;
        c->message_size = n + 4;
    }
    size_t n = c->message_size - offset;
    if (n > out.size)
        n = out.size;
    memcpy(out.data, c->message + offset, n);
    turtle_progress p = progress(1, 0, n);
    if (offset + n < c->message_size)
        p.status = TURTLE_MORE;
    return p;
}
static turtle_progress process(turtle_connection* c, unsigned type, turtle_bytes in, int last) {
    if (c->received + in.size > c->owner->options.max_message)
        return progress(0, 0, 0);
    memcpy(c->message + c->received, in.data, in.size);
    c->received += in.size;
    if (!last) {
        turtle_progress p = {TURTLE_MORE, in.size, 0, 0};
        return p;
    }
    size_t fragment_size = in.size;
    in.data = c->message;
    in.size = c->received;
    if (in.size < 4)
        return progress(0, 0, 0);
    mbedtls_ssl_context* s = &c->ssl;
    unsigned char *b = (unsigned char*)in.data + 4, *end = (unsigned char*)in.data + in.size;
    int rc = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    switch (type) {
    case 1:
        rc = ssl_tls13_parse_client_hello(s, b, end, 0);
        break;
    case 2:
        rc = ssl_tls13_parse_server_hello(s, b, end, 0);
        break;
    case 8:
        rc = ssl_tls13_parse_encrypted_extensions(s, b, end);
        break;
    case 13:
        rc = ssl_tls13_parse_certificate_request(s, b, end);
        s->handshake->client_auth = 1;
        break;
    case 11:
        rc = mbedtls_ssl_tls13_parse_certificate(s, b, end);
        break;
    case 15: {
        unsigned char hash[64], verify[146];
        size_t hn = 0, vn = 0;
        rc = mbedtls_ssl_get_handshake_transcript(
            s, (mbedtls_md_type_t)s->handshake->ciphersuite_info->mac, hash, sizeof(hash), &hn);
        if (!rc) {
            ssl_tls13_create_verify_structure(hash, hn, verify, &vn,
                                              c->owner->options.role == TURTLE_CLIENT
                                                  ? MBEDTLS_SSL_IS_SERVER
                                                  : MBEDTLS_SSL_IS_CLIENT);
            rc = ssl_tls13_parse_certificate_verify(s, b, end, verify, vn);
        }
        break;
    }
    case 20:
        rc = ssl_tls13_parse_finished_message(s, b, end);
        break;
    }
    return progress(checked(c, rc), rc ? 0 : fragment_size, 0);
}
static void increment(unsigned char ctr[8]) {
    for (int i = 7; i >= 0; --i)
        if (++ctr[i])
            break;
}
static turtle_progress protect(turtle_connection* c, unsigned type, turtle_bytes in,
                               turtle_buffer out) {
    mbedtls_ssl_context* s = &c->ssl;
    mbedtls_record rec = {0};
    if (out.size < in.size + 32)
        return progress(0, 0, 0);
    rec.buf = out.data + 5;
    rec.buf_len = out.size - 5;
    rec.data_len = in.size;
    rec.type = type;
    rec.ver[0] = 3;
    rec.ver[1] = 3;
    memcpy(rec.ctr, s->cur_out_ctr, 8);
    memcpy(rec.buf, in.data, in.size);
    if (s->transform_out && !checked(c, mbedtls_ssl_encrypt_buf(s, s->transform_out, &rec,
                                                                s->conf->f_rng, s->conf->p_rng)))
        return progress(0, 0, 0);
    increment(s->cur_out_ctr);
    out.data[0] = rec.type;
    out.data[1] = 3;
    out.data[2] = 3;
    out.data[3] = (rec.data_len >> 8) & 255;
    out.data[4] = rec.data_len & 255;
    return progress(1, in.size, rec.data_len + 5);
}
static turtle_progress unprotect(turtle_connection* c, turtle_bytes in, turtle_buffer out,
                                 unsigned* type) {
    mbedtls_ssl_context* s = &c->ssl;
    mbedtls_record rec = {0};
    if (in.size < 5 || out.size < in.size)
        return progress(0, 0, 0);
    rec.buf = out.data;
    rec.buf_len = out.size;
    rec.data_len = in.size - 5;
    rec.type = in.data[0];
    rec.ver[0] = in.data[1];
    rec.ver[1] = in.data[2];
    memcpy(rec.ctr, s->in_ctr, 8);
    memcpy(rec.buf, in.data + 5, in.size - 5);
    if (s->transform_in && !checked(c, mbedtls_ssl_decrypt_buf(s, s->transform_in, &rec)))
        return progress(0, 0, 0);
    increment(s->in_ctr);
    memmove(out.data, rec.buf + rec.data_offset, rec.data_len);
    *type = rec.type;
    return progress(1, in.size, rec.data_len);
}
static turtle_result result(const turtle_connection* c) {
    turtle_result r = {0};
    r.full_handshake = c->complete;
    r.peer_certificate = mbedtls_ssl_get_peer_cert(&c->ssl) != NULL;
    r.peer_verified = r.peer_certificate && mbedtls_ssl_get_verify_result(&c->ssl) == 0;
    return r;
}
static turtle_storage storage(const turtle_connection* c) {
    turtle_storage r = {0};
    r.message_buffer_bytes = c->owner->options.max_message;
    r.storage_available = 1 | 4;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    r.record_buffer_bytes =
        mbedtls_ssl_get_input_buflen(&c->ssl) + mbedtls_ssl_get_output_buflen(&c->ssl);
#else
    r.record_buffer_bytes = MBEDTLS_SSL_IN_BUFFER_LEN + MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif
    r.storage_available |= 2;
    return r;
}
static const char* error(const turtle_connection* c) {
    return c->error;
}
turtle_implementation turtle_register(void) {
    turtle_implementation a = {support,
                               create_context,
                               destroy_context,
                               create_connection,
                               destroy_connection,
                               transition,
                               assemble,
                               process,
                               protect,
                               unprotect,
                               result,
                               storage,
                               error};
    return a;
}
