#ifndef TURTLE_IMPLEMENTATION_H
#define TURTLE_IMPLEMENTATION_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#include "role_types.h"

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
