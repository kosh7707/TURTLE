#ifndef TURTLE_IMPLEMENTATION_H
#define TURTLE_IMPLEMENTATION_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum turtle_role { TURTLE_CLIENT, TURTLE_SERVER } turtle_role;
enum { TURTLE_TLS13 = 0x0304, TURTLE_WANT_READ = -2, TURTLE_WANT_WRITE = -3 };
/* Declared full certificate handshake policy; never an inference from a record
 * number. No resumption, HRR, client early data or session tickets. */
typedef enum turtle_handshake_profile {
    TURTLE_PROFILE_UNSPECIFIED = 0,
    TURTLE_PROFILE_SERVER_AUTH_1RTT = 1,
    TURTLE_PROFILE_MTLS_1RTT = 2
} turtle_handshake_profile;
typedef enum turtle_hook {
    TURTLE_BIO_BEGIN, TURTLE_BIO_END, TURTLE_IO_BEGIN, TURTLE_IO_END,
    TURTLE_RECORD_HEADER, TURTLE_HANDSHAKE_MESSAGE
} turtle_hook;

/* Synchronous, calling-thread-only borrowed transport. Positive transfer counts
 * may be partial. Zero denotes EOF, -1 failure, WANT_* a readiness wait.
 * The optional observer must not change the TLS result. BEGIN/END delimit a
 * library I/O call, not a syscall. size is the requested count, processed is
 * zero on entry and the actual count/error on exit; data is NULL. Header and
 * message data are borrowed only for the callback (do not retain pointers).
 * sending=1 means outgoing. Absence of an optional hook is not zero events. */
typedef struct turtle_transport {
    void* state;
    ptrdiff_t (*receive)(void*, void*, size_t);
    ptrdiff_t (*send)(void*, const void*, size_t);
    void (*observe)(void* state, turtle_hook, int sending, const void* data,
                    size_t size, ptrdiff_t processed);
    int mutual_auth;            /* policy: 0 server auth only, 1 mutual auth */
} turtle_transport;
enum { TURTLE_UNPADDED_APPLICATION_TAIL = 1 };
typedef struct turtle_handshake_info {
    uint16_t version;
    int resumed;                /* 0 full; 1 resumed; -1 unknown */
    const char* cipher;          /* borrowed until release; NULL unsupported */
    const char* group;
    turtle_handshake_profile profile;
    int peer_verified;          /* 1 authenticated; 0 not verified; -1 unknown */
    /* Local sender policy for bounded successful tasks: no padding, empty app
     * records or post-handshake messages before shutdown. Both peers must
     * attest before an analyzer uses this to locate a Finished boundary. */
    int record_policy;          /* TURTLE_UNPADDED_APPLICATION_TAIL or 0 unknown */
} turtle_handshake_info;

/* Source contract (not a binary plugin ABI). prepare creates one connection;
 * failure returns NULL after cleaning up. argv and transport live until release.
 * prepare/release must not do network I/O. The framework owns all buffers.
 * handshake may return 1 only after enforcing the configured peer authentication
 * policy, including required client verification on a mutual-auth server. This
 * permits serving a verified request immediately, without querying mid-task.
 * TLS operations may return WANT_READ or
 * WANT_WRITE; retry the SAME operation with the same buffer and length after
 * readiness. Only a positive transfer advances the plaintext offset. read=0
 * means EOF, not progress. Other nonpositive values are fatal.
 * query returns 1 and fills the negotiated/authentication result on the live
 * connection after the measured interval. shutdown is optional and outside it.
 * Optional server_first replaces the INITIAL server handshake step in S2/S4:
 * it drives the server flight and submits the supplied greeting before client
 * authentication is complete. A positive return counts submitted plaintext.
 * After the whole greeting is written, call handshake to completion and verify
 * the peer before serving requests. Never send secrets via server_first. */
typedef struct turtle_implementation {
    const char* name;
    void* (*prepare)(turtle_role, int argc, const char* const* argv, turtle_transport);
    void (*release)(void*);
    int (*handshake)(void*);
    ptrdiff_t (*read)(void*, void*, size_t);
    ptrdiff_t (*write)(void*, const void*, size_t);
    int (*shutdown)(void*);
    int (*query)(void*, turtle_handshake_info*);
    ptrdiff_t (*server_first)(void*, const void*, size_t);
    unsigned hooks;             /* supported observer events, 1u << turtle_hook */
} turtle_implementation;
#ifdef __cplusplus
}
#endif
#endif
