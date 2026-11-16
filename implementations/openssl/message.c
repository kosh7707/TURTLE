/* The pinned OpenSSL private headers are intentionally confined to this backend. */
#include "internal/ssl_unwrap.h"
#include "ssl_local.h"
#include "statem/statem_local.h"
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <turtle/implementation.h>

#ifndef TURTLE_OPENSSL_NAME
#define TURTLE_OPENSSL_NAME "openssl"
#endif
struct turtle_context {
    SSL_CTX* ctx;
    turtle_options options;
};
struct turtle_connection {
    size_t received;
    turtle_context* owner;
    SSL* ssl;
    SSL_CONNECTION* state;
    BIO *input, *output;
    int process_result;
    int complete;
    char error[256];
};
static int fail(turtle_connection* c, const char* stage) {
    unsigned long code = ERR_peek_last_error();
    snprintf(c->error, sizeof(c->error), "%s: %s", stage,
             code ? ERR_reason_error_string(code) : "boundary operation failed");
    return 0;
}
static turtle_progress progress(int ok, size_t consumed, size_t produced) {
    turtle_progress p = {ok ? TURTLE_DONE : TURTLE_ERROR, consumed, produced, ok ? 0 : -1};
    return p;
}
static turtle_support support(void) {
    turtle_support s = {TURTLE_OPENSSL_NAME, OPENSSL_VERSION_TEXT, "standard-tls13"};
    return s;
}
static turtle_context* create_context(const turtle_options* o, char* error, size_t n) {
    turtle_context* c = OPENSSL_zalloc(sizeof(*c));
    if (c == NULL)
        return NULL;
    c->options = *o;
    c->ctx = SSL_CTX_new(TLS_method());
    if (c->ctx == NULL)
        goto bad;
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(c->ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(c->ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
    SSL_CTX_clear_options(c->ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
    SSL_CTX_set_num_tickets(c->ctx, 0);
    SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(c->ctx,
                       o->role == TURTLE_CLIENT || o->mutual_auth
                           ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
                           : SSL_VERIFY_NONE,
                       NULL);
    if (!SSL_CTX_set_ciphersuites(c->ctx, "TLS_AES_128_GCM_SHA256") ||
        !SSL_CTX_set1_groups_list(c->ctx, o->group) ||
        !SSL_CTX_set1_sigalgs_list(c->ctx, "ecdsa_secp256r1_sha256"))
        goto bad;
    if ((o->role == TURTLE_CLIENT || o->mutual_auth) &&
        !SSL_CTX_load_verify_locations(c->ctx, o->ca_file, NULL))
        goto bad;
    if ((o->role == TURTLE_SERVER || o->mutual_auth) &&
        (!SSL_CTX_use_certificate_chain_file(c->ctx, o->certificate_file) ||
         !SSL_CTX_use_PrivateKey_file(c->ctx, o->private_key_file, SSL_FILETYPE_PEM) ||
         !SSL_CTX_check_private_key(c->ctx)))
        goto bad;
    return c;
bad:
    snprintf(error, n, "OpenSSL context: %s", ERR_reason_error_string(ERR_peek_last_error()));
    SSL_CTX_free(c->ctx);
    OPENSSL_free(c);
    return NULL;
}
static void destroy_context(turtle_context* c) {
    SSL_CTX_free(c->ctx);
    OPENSSL_free(c);
}
static turtle_connection* create_connection(turtle_context* owner, char* error, size_t n) {
    turtle_connection* c = OPENSSL_zalloc(sizeof(*c));
    if (c == NULL)
        return NULL;
    c->owner = owner;
    c->ssl = SSL_new(owner->ctx);
    c->state = SSL_CONNECTION_FROM_SSL(c->ssl);
    c->input = BIO_new(BIO_s_mem());
    c->output = BIO_new(BIO_s_mem());
    if (!c->state || !c->input || !c->output) {
        snprintf(error, n, "OpenSSL connection allocation");
        SSL_free(c->ssl);
        BIO_free(c->input);
        BIO_free(c->output);
        OPENSSL_free(c);
        return NULL;
    }
    SSL_set_bio(c->ssl, c->input, c->output);
    c->state->turtle_boundary = 1;
    if (owner->options.role == TURTLE_CLIENT) {
        SSL_set_connect_state(c->ssl);
        SSL_set_tlsext_host_name(c->ssl, owner->options.server_name);
        SSL_set1_host(c->ssl, owner->options.server_name);
    } else
        SSL_set_accept_state(c->ssl);
    return c;
}
static void destroy_connection(turtle_connection* c) {
    SSL_free(c->ssl);
    OPENSSL_free(c);
}
static int transition(turtle_connection* c, turtle_transition op, unsigned type, turtle_bytes msg) {
    SSL_CONNECTION* s = c->state;
    WORK_STATE work;
    switch (op) {
    case TURTLE_BEGIN:
        s->init_buf = BUF_MEM_new();
        if (!s->init_buf || !BUF_MEM_grow(s->init_buf, c->owner->options.max_message) ||
            !tls_setup_handshake(s))
            return fail(c, "initialize");
        s->statem.state = MSG_FLOW_WRITING;
        s->statem.in_handshake = 1;
        return 1;
    case TURTLE_PREPARE_SEND:
        if ((s->server ? ossl_statem_server_write_transition(s)
                       : ossl_statem_client_write_transition(s)) != WRITE_TRAN_CONTINUE)
            return fail(c, "send transition");
        work = s->server ? ossl_statem_server_pre_work(s, WORK_MORE_A)
                         : ossl_statem_client_pre_work(s, WORK_MORE_A);
        if (work != WORK_FINISHED_CONTINUE)
            return fail(c, "send pre-work");
        (void)type;
        return 1;
    case TURTLE_COMMIT_SEND:
        if (!ssl3_finish_mac(s, msg.data, msg.size))
            return fail(c, "send transcript");
        work = s->server ? ossl_statem_server_post_work(s, WORK_MORE_A)
                         : ossl_statem_client_post_work(s, WORK_MORE_A);
        return work == WORK_FINISHED_CONTINUE ? 1 : fail(c, "send post-work");
    case TURTLE_PREPARE_RECEIVE:
        c->received = 0;
        if (!(s->server ? ossl_statem_server_read_transition(s, (int)type)
                        : ossl_statem_client_read_transition(s, (int)type)))
            return fail(c, "receive transition");
        if (!BUF_MEM_grow(s->init_buf, msg.size))
            return fail(c, "message capacity");
        memcpy(s->init_buf->data, msg.data, msg.size);
        s->init_msg = s->init_buf->data + 4;
        s->init_num = msg.size - 4;
        s->s3.tmp.message_type = type;
        s->s3.tmp.message_size = msg.size - 4;
        if (type == TURTLE_FINISHED && !ssl3_take_mac(s))
            return fail(c, "finished pre-work");
        if (!ssl3_finish_mac(s, msg.data, msg.size))
            return fail(c, "receive transcript");
        s->first_packet = 0;
        return 1;
    case TURTLE_COMMIT_RECEIVE:
        if (type == TURTLE_SERVER_HELLO && !turtle_openssl_server_hello_post(s))
            return fail(c, "server hello key transition");
        if (type == TURTLE_FINISHED && turtle_openssl_finished_post(s, 1) == MSG_PROCESS_ERROR)
            return fail(c, "finished key transition");
        if (c->process_result == MSG_PROCESS_CONTINUE_PROCESSING) {
            work = s->server ? ossl_statem_server_post_process_message(s, WORK_MORE_A)
                             : ossl_statem_client_post_process_message(s, WORK_MORE_A);
            if (work != WORK_FINISHED_CONTINUE && work != WORK_FINISHED_SWAP &&
                work != WORK_FINISHED_STOP)
                return fail(c, "receive post-work");
        }
        s->init_num = 0;
        return 1;
    case TURTLE_FINISH:
        s->statem.hand_state = TLS_ST_OK;
        if (tls_finish_handshake(s, WORK_MORE_A, 0, 1) == WORK_ERROR)
            return fail(c, "finish");
        s->statem.state = MSG_FLOW_FINISHED;
        s->statem.in_handshake = 0;
        c->complete = 1;
        return 1;
    }
    return fail(c, "unknown transition");
}
turtle_progress turtle_openssl_assemble(turtle_connection* c, unsigned type, size_t offset,
                                        turtle_buffer out) {
    SSL_CONNECTION* s = c->state;
    if (offset == 0) {
        WPACKET pkt;
        confunc_f constructor = NULL;
        int mt;
        if (!(s->server ? ossl_statem_server_construct_message(s, &constructor, &mt)
                        : ossl_statem_client_construct_message(s, &constructor, &mt)) ||
            mt != (int)type)
            return progress(fail(c, "select constructor"), 0, 0);
        if (!WPACKET_init(&pkt, s->init_buf) || !ssl_set_handshake_header(s, &pkt, mt))
            return progress(fail(c, "message header"), 0, 0);
        if (constructor && constructor(s, &pkt) != CON_FUNC_SUCCESS) {
            WPACKET_cleanup(&pkt);
            return progress(fail(c, "construct"), 0, 0);
        }
        if (!ssl_close_construct_packet(s, &pkt, mt) || !WPACKET_finish(&pkt)) {
            WPACKET_cleanup(&pkt);
            return progress(fail(c, "message finish"), 0, 0);
        }
    }
    size_t total = s->init_num;
    if (offset > total)
        return progress(fail(c, "assembly offset"), 0, 0);
    size_t n = total - offset < out.size ? total - offset : out.size;
    memcpy(out.data, s->init_buf->data + offset, n);
    turtle_progress p = progress(1, 0, n);
    if (offset + n < total)
        p.status = TURTLE_MORE;
    return p;
}
static turtle_progress process(turtle_connection* c, unsigned type, turtle_bytes in, int last) {
    SSL_CONNECTION* s = c->state;
    PACKET pkt;
    (void)type;
    c->received += in.size;
    if (!last) {
        turtle_progress p = {TURTLE_MORE, in.size, 0, 0};
        return p;
    }
    if (c->received != s->s3.tmp.message_size + 4 ||
        !PACKET_buf_init(&pkt, (unsigned char*)s->init_msg, s->init_num))
        return progress(fail(c, "incomplete received message"), 0, 0);
    c->process_result = s->server ? ossl_statem_server_process_message(s, &pkt)
                                  : ossl_statem_client_process_message(s, &pkt);
    if (c->process_result == MSG_PROCESS_ERROR)
        return progress(fail(c, "process"), 0, 0);
    return progress(1, in.size, 0);
}
static turtle_progress protect(turtle_connection* c, unsigned type, turtle_bytes in,
                               turtle_buffer out) {
    SSL_CONNECTION* s = c->state;
    OSSL_RECORD_TEMPLATE rec;
    rec.type = type;
    rec.version = TLS1_2_VERSION;
    rec.buf = in.data;
    rec.buflen = in.size;
    if (s->rlayer.wrlmethod->write_records(s->rlayer.wrl, &rec, 1) != OSSL_RECORD_RETURN_SUCCESS)
        return progress(fail(c, "record protection"), 0, 0);
    size_t n = BIO_ctrl_pending(c->output), got = 0;
    if (n > out.size || !BIO_read_ex(c->output, out.data, n, &got) || got != n)
        return progress(fail(c, "record output capacity"), 0, 0);
    return progress(1, in.size, got);
}
static turtle_progress unprotect(turtle_connection* c, turtle_bytes in, turtle_buffer out,
                                 unsigned* type) {
    SSL_CONNECTION* s = c->state;
    void* handle = NULL;
    const unsigned char* data = NULL;
    size_t n = 0;
    int version;
    uint8_t rt;
    if (BIO_write(c->input, in.data, (int)in.size) != (int)in.size ||
        s->rlayer.rrlmethod->read_record(s->rlayer.rrl, &handle, &version, &rt, &data, &n, NULL,
                                         NULL) != OSSL_RECORD_RETURN_SUCCESS)
        return progress(fail(c, "record unprotection"), 0, 0);
    if (n > out.size)
        return progress(fail(c, "plaintext capacity"), 0, 0);
    memcpy(out.data, data, n);
    if (s->rlayer.rrlmethod->release_record(s->rlayer.rrl, handle, n) != OSSL_RECORD_RETURN_SUCCESS)
        return progress(fail(c, "release record"), 0, 0);
    *type = rt;
    return progress(1, in.size, n);
}
static turtle_result result(const turtle_connection* c) {
    turtle_result r = {0};
    r.full_handshake =
        c->complete && SSL_version(c->ssl) == TLS1_3_VERSION && !SSL_session_reused(c->ssl);
    r.peer_certificate = SSL_get0_peer_certificate(c->ssl) != NULL;
    r.peer_verified = r.peer_certificate && SSL_get_verify_result(c->ssl) == X509_V_OK;
    return r;
}
static turtle_storage storage(const turtle_connection* c) {
    turtle_storage r = {0};
    r.message_buffer_bytes = c->state->init_buf ? c->state->init_buf->max : 0;
    r.storage_available = 1 | 4;
    return r;
}
static const char* error(const turtle_connection* c) {
    return c->error;
}
turtle_implementation turtle_register(void) {
    turtle_implementation api = {support,
                                 create_context,
                                 destroy_context,
                                 create_connection,
                                 destroy_connection,
                                 transition,
                                 turtle_openssl_assemble,
                                 process,
                                 protect,
                                 unprotect,
                                 result,
                                 storage,
                                 error};
    return api;
}
