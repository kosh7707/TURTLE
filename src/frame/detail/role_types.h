#ifndef TURTLE_ROLE_TYPES_H
#define TURTLE_ROLE_TYPES_H
#include <stddef.h>
enum { TURTLE_WANT_READ = -2, TURTLE_WANT_WRITE = -3 };
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
#endif
