#include <wolfssl/options.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <turtle/implementation.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#ifndef TURTLE_BACKEND_NAME
#define TURTLE_BACKEND_NAME "wolfssl"
#endif
struct turtle_context {
    turtle_options options;
    WOLFSSL_CTX* ctx;
};
struct turtle_connection {
    size_t received;
    turtle_context* owner;
    WOLFSSL* ssl;
    unsigned char* message;
    int protected_write, protected_read, complete;
    char error[256];
};
static int checked(turtle_connection* c, int rc) {
    if (rc) {
        wolfSSL_ERR_error_string_n((unsigned long)rc, c->error, sizeof(c->error));
        return 0;
    }
    return 1;
}
static turtle_progress progress(int ok, size_t consumed, size_t produced) {
    turtle_progress p = {ok ? TURTLE_DONE : TURTLE_ERROR, consumed, produced, ok ? 0 : -1};
    return p;
}
static turtle_support support(void) {
    turtle_support s = {TURTLE_BACKEND_NAME, LIBWOLFSSL_VERSION_STRING,
#ifdef TURTLE_MLKEM
                        "ML-KEM-768"
#elif defined(TURTLE_BITHAC_CACHED)
                        "BiTHaC-CI-SSC-cache"
#else
                        "standard-tls13"
#endif
    };
    return s;
}
static void destroy_context(turtle_context* c) {
#ifdef TURTLE_BITHAC_CACHED
    if (c->ctx)
        TurtleCiDestroy(c->ctx);
#endif
    wolfSSL_CTX_free(c->ctx);
    wolfSSL_Cleanup();
    free(c);
}
static turtle_context* create_context(const turtle_options* o, char* error, size_t n) {
    turtle_context* c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->options = *o;
    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        goto bad;
    c->ctx = wolfSSL_CTX_new(o->role == TURTLE_CLIENT ? wolfTLSv1_3_client_method()
                                                      : wolfTLSv1_3_server_method());
    if (!c->ctx)
        goto bad;
    int group = WOLFSSL_ECC_SECP256R1;
#ifdef TURTLE_MLKEM
    group = WOLFSSL_ML_KEM_768;
    if (strcmp(o->group, "ML-KEM-768"))
        goto bad;
#else
    if (strcmp(o->group, "P-256") && strcmp(o->group, "secp256r1"))
        goto bad;
#endif
#ifdef TURTLE_BITHAC_CACHED
    if (TurtleCiCreate(c->ctx) != 0)
        goto bad;
#endif
    if (wolfSSL_CTX_set_cipher_list(c->ctx, "TLS13-AES128-GCM-SHA256") != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_set_groups(c->ctx, &group, 1) != WOLFSSL_SUCCESS)
        goto bad;
    if ((o->role == TURTLE_CLIENT || o->mutual_auth) &&
        wolfSSL_CTX_load_verify_locations(c->ctx, o->ca_file, NULL) != WOLFSSL_SUCCESS)
        goto bad;
    if ((o->role == TURTLE_SERVER || o->mutual_auth) &&
        (wolfSSL_CTX_use_certificate_chain_file(c->ctx, o->certificate_file) != WOLFSSL_SUCCESS ||
         wolfSSL_CTX_use_PrivateKey_file(c->ctx, o->private_key_file, WOLFSSL_FILETYPE_PEM) !=
             WOLFSSL_SUCCESS))
        goto bad;
    wolfSSL_CTX_set_verify(c->ctx,
                           o->role == TURTLE_CLIENT || o->mutual_auth
                               ? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
                               : WOLFSSL_VERIFY_NONE,
                           NULL);
    wolfSSL_CTX_set_session_cache_mode(c->ctx, WOLFSSL_SESS_CACHE_OFF);
    if (o->role == TURTLE_SERVER) {
        wolfSSL_CTX_no_ticket_TLSv13(c->ctx);
        wolfSSL_CTX_set_num_tickets(c->ctx, 0);
    }
    return c;
bad:
    snprintf(error, n, "wolfSSL context preparation failed");
    destroy_context(c);
    return NULL;
}
static void destroy_connection(turtle_connection* c) {
    wolfSSL_free(c->ssl);
    free(c->message);
    free(c);
}
static turtle_connection* create_connection(turtle_context* owner, char* error, size_t n) {
    turtle_connection* c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->owner = owner;
    c->ssl = wolfSSL_new(owner->ctx);
    c->message = malloc(owner->options.max_message);
    if (!c->ssl || !c->message) {
        snprintf(error, n, "wolfSSL connection preparation failed");
        destroy_connection(c);
        return NULL;
    }
    c->ssl->turtle_message = c->message;
    c->ssl->turtle_capacity = (word32)owner->options.max_message;
    c->ssl->turtle_boundary = 2;
    if (owner->options.role == TURTLE_CLIENT) {
#ifdef TURTLE_BITHAC_CACHED
        wolfSSL_CI_set_peer_id(c->ssl, owner->options.server_name);
#endif
        wolfSSL_check_domain_name(c->ssl, owner->options.server_name);
        wolfSSL_UseSNI(c->ssl, WOLFSSL_SNI_HOST_NAME, owner->options.server_name,
                       (unsigned short)strlen(owner->options.server_name));
    }
    return c;
}
static int transition(turtle_connection* c, turtle_transition op, unsigned type,
                      turtle_bytes message) {
    WOLFSSL* s = c->ssl;
    int rc = 0;
    switch (op) {
    case TURTLE_BEGIN:
        break;
    case TURTLE_PREPARE_SEND:
        s->turtle_boundary = 1;
        s->turtle_length = 0;
        s->buffers.outputBuffer.length = 0;
        s->buffers.outputBuffer.idx = 0;
        break;
    case TURTLE_PREPARE_RECEIVE:
        c->received = 0;
        s->turtle_boundary = 2;
        break;
    case TURTLE_COMMIT_SEND:
    case TURTLE_COMMIT_RECEIVE:
        s->turtle_boundary = 0;
        rc = HashRaw(s, message.data, (int)message.size);
        if (!rc)
            rc = TurtleWolfCommit(s, type, op == TURTLE_COMMIT_SEND);
        s->turtle_boundary = 2;
        if (type == 2)
            c->protected_write = c->protected_read = 1;
        break;
    case TURTLE_FINISH:
#ifdef TURTLE_BITHAC_CACHED
        rc = TurtleCiFinish(s);
#endif
        s->options.handShakeDone = 1;
        s->options.handShakeState = HANDSHAKE_DONE;
        c->complete = 1;
        break;
    }
    return checked(c, rc);
}
static turtle_progress assemble(turtle_connection* c, unsigned type, size_t offset,
                                turtle_buffer out) {
    if (!offset) {
        int rc = TurtleWolfBuild(c->ssl, (int)type);
        if (!checked(c, rc))
            return progress(0, 0, 0);
    }
    size_t n = c->ssl->turtle_length - offset;
    if (n > out.size)
        n = out.size;
    memcpy(out.data, c->message + offset, n);
    turtle_progress p = progress(1, 0, n);
    if (offset + n < c->ssl->turtle_length)
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
    int rc = TurtleWolfProcess(c->ssl, type, (byte*)in.data, (word32)in.size);
    return progress(checked(c, rc), rc ? 0 : fragment_size, 0);
}
static turtle_progress protect(turtle_connection* c, unsigned type, turtle_bytes in,
                               turtle_buffer out) {
    if (out.size < in.size + 32)
        return progress(0, 0, 0);
    if (!c->protected_write) {
        out.data[0] = type;
        out.data[1] = 3;
        out.data[2] = 3;
        out.data[3] = (in.size >> 8) & 255;
        out.data[4] = in.size & 255;
        memcpy(out.data + 5, in.data, in.size);
        return progress(1, in.size, in.size + 5);
    }
    c->ssl->turtle_boundary = 0;
    int n =
        BuildTls13Message(c->ssl, out.data, (int)out.size, in.data, (int)in.size, type, 0, 0, 0);
    c->ssl->turtle_boundary = 2;
    if (n < 0)
        return progress(checked(c, n), 0, 0);
    return progress(1, in.size, (size_t)n);
}
static turtle_progress unprotect(turtle_connection* c, turtle_bytes in, turtle_buffer out,
                                 unsigned* type) {
    if (in.size < 5 || out.size < in.size)
        return progress(0, 0, 0);
    if (!c->protected_read) {
        memcpy(out.data, in.data + 5, in.size - 5);
        *type = in.data[0];
        return progress(1, in.size, in.size - 5);
    }
    c->ssl->turtle_boundary = 0;
    int rc = DecryptTls13(c->ssl, out.data, in.data + 5, (word16)(in.size - 5), in.data, 5);
    c->ssl->turtle_boundary = 2;
    if (!checked(c, rc))
        return progress(0, 0, 0);
    size_t n = in.size - 5 - c->ssl->specs.aead_mac_size;
    while (n && out.data[n - 1] == 0)
        --n;
    if (!n)
        return progress(0, 0, 0);
    *type = out.data[--n];
    return progress(1, in.size, n);
}
static turtle_result result(const turtle_connection* c) {
    turtle_result r = {0};
    r.full_handshake = c->complete && !c->ssl->options.resuming;
    r.peer_certificate = c->ssl->options.havePeerCert;
    r.peer_verified = r.peer_certificate && c->ssl->options.peerAuthGood;
#ifdef TURTLE_MLKEM
    r.keygen = c->ssl->turtle_kem[0];
    r.encapsulate = c->ssl->turtle_kem[1];
    r.decapsulate = c->ssl->turtle_kem[2];
    r.optimized = c->ssl->turtle_kem[3];
    r.technique_used = r.keygen || r.encapsulate || r.decapsulate;
#endif
#ifdef TURTLE_BITHAC_CACHED
    r.technique_used = c->ssl->ci_cert_cache_hit_c || c->ssl->ci_cert_cache_hit_s;
#endif
#ifdef TURTLE_BITHAC_CACHED
    r.certificate_cache_hit = c->ssl->ci_cert_cache_hit_c || c->ssl->ci_cert_cache_hit_s;
    r.request_cache_hit = c->ssl->ci_cert_req_cache_hit_c || c->ssl->ci_cert_req_cache_hit_s;
    r.ssc_cache_hit = c->ssl->ssc_cache_hit_cert_c || c->ssl->ssc_cache_hit_cert_s;
#endif
    return r;
}
static turtle_storage storage(const turtle_connection* c) {
    turtle_storage r = {0};
    r.message_buffer_bytes = c->owner->options.max_message;
    r.storage_available = 1 | 4;
    r.record_buffer_bytes =
        c->ssl->buffers.inputBuffer.bufferSize + c->ssl->buffers.outputBuffer.bufferSize;
    r.storage_available |= 2;
#ifdef TURTLE_BITHAC_CACHED
    r.cache_bytes = TurtleCiBytes(c->owner->ctx);
#endif
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
