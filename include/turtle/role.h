#ifndef TURTLE_ROLE_H
#define TURTLE_ROLE_H
#include "role_types.h"
#include "io_boundary.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct turtle_session turtle_session;
typedef struct turtle_config {
    turtle_role role;
    int mutual_auth, check;
    const char *host;
    uint16_t port;
    int argc;
    const char *const *argv; /* implementation-specific arguments after -- */
} turtle_config;
typedef enum turtle_op {
    TURTLE_DONE, TURTLE_HS, TURTLE_FIRST_HS, TURTLE_FIRST_WRITE,
    TURTLE_READ, TURTLE_WRITE, TURTLE_SHUTDOWN
} turtle_op;
typedef struct turtle_action {
    turtle_op op;
    const void *out;
    void *in;
    size_t size;
} turtle_action;
typedef enum turtle_disposition {
    TURTLE_ERROR, TURTLE_EOF, TURTLE_AGAIN_READ, TURTLE_AGAIN_WRITE, TURTLE_OK
} turtle_disposition;
typedef struct turtle_result {
    turtle_disposition status;
    size_t bytes; /* successful plaintext only; HS and shutdown: 0 */
    int allow_other; /* public TLS path explicitly permits another application operation */
} turtle_result;

/* All handles, buffers and TLS calls are single-threaded. No TLS object is ever
 * passed to the SDK. NULL open means invalid invocation. Names are copied. */
turtle_session *turtle_session_open(int argc, char **argv, const char *name,
                                    unsigned hook_mask, int server_first_supported);
const turtle_config *turtle_session_config(const turtle_session *);
/* Optional built-in TCP transport, or app-owned socket: report the actual
 * listening port before accept and attach the borrowed connected fd. The SDK
 * never closes that original fd. For --check, transport is offline. */
int turtle_session_bound(turtle_session *, uint16_t port);
int turtle_session_attach(turtle_session *, int connected_fd);
int turtle_session_transport(turtle_session *, turtle_transport *);
/* Report actual TLS setup success (even on --check). Return 1 to continue,
 * 0 for successful check, -1 on failure. */
int turtle_session_bind_counts(turtle_session *, const turtle_io_boundary *); /* NULL detaches */
/* App-owned native transports not using turtle_session_transport: notify a
 * successful ciphertext transfer (not the corresponding count hook). */
int turtle_session_wire(turtle_session *, int sending, const void *, size_t);
/* Optional alternative to wire() for detailed records with an app-owned fd.
 * Bracket EACH real send/recv (including EINTR retries), not a BIO callback.
 * before borrows the syscall buffer through returned; returned takes the raw
 * syscall count (-1 on error) immediately, before translating errno. Both
 * preserve errno. Keep count hooks separate. Never mix interval, byte-only
 * and built-in wire sources on one connection. */
int turtle_socket_before(turtle_session *, int sending, const void *buffer, size_t requested);
int turtle_socket_returned(turtle_session *, ptrdiff_t syscall_result);
int turtle_session_ready(turtle_session *, int prepared);
/* One pull = one native TLS operation. FIRST_HS prepares the public server
 * flight; FIRST_WRITE uses the same validated server-first path. HS completes
 * authentication. SHUTDOWN is outside the measurement. pull waits for necessary
 * readiness itself. Return 1 on success (including DONE), -1 on failure. */
int turtle_pull(turtle_session *, turtle_action *);
void turtle_before(turtle_session *);
void turtle_returned(turtle_session *);
/* Bracket only the raw TLS call. Translate errors and gather public facts
 * afterwards. A successful HS must supply negotiated/authentication facts;
 * a FIRST_HS that already completed TLS may also supply them. */
int turtle_submit(turtle_session *, turtle_result, const turtle_handshake_info *facts);
/* Close writes the endpoint result; returns process exit code (0 success). */
int turtle_session_close(turtle_session *);
#ifdef __cplusplus
}
#endif
#endif
