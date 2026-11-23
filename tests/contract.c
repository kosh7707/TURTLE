#include <turtle/endpoint.h>
#include <string.h>

_Static_assert(TURTLE_TLS13 == 0x0304, "normalized protocol");
_Static_assert(TURTLE_WANT_READ < -1 && TURTLE_WANT_WRITE < -1 &&
               TURTLE_WANT_READ != TURTLE_WANT_WRITE, "distinct readiness results");

/* Compile-time example of a C-only external adapter. This fixture tests the
 * source contract, not TLS or authentication. No optional hooks are needed. */
static unsigned prepares, releases;
static void *prepare(turtle_role role, int argc, const char *const *argv, turtle_transport transport) {
    (void)role; (void)argc; (void)argv;
    ++prepares;
    return transport.state;
}
static void release(void *state) { if (state) ++releases; }
static int handshake(void *state) { (void)state; return TURTLE_WANT_READ; }
static ptrdiff_t read_bytes(void *s, void *b, size_t n) {
    (void)s; (void)b; (void)n; return TURTLE_WANT_READ;
}
static ptrdiff_t write_bytes(void *s, const void *b, size_t n) {
    (void)s; (void)b; (void)n; return TURTLE_WANT_WRITE;
}
static int query(void *s, turtle_handshake_info *out) {
    (void)s; memset(out, 0, sizeof(*out)); out->peer_verified = -1; return 0;
}
static const turtle_implementation fixture = {
    .name = "contract-only", .prepare = prepare, .release = release,
    .handshake = handshake, .read = read_bytes, .write = write_bytes, .query = query
};
int main(void) {
    char *args[] = {"contract_only", "--role", "client", "--check", NULL};
    turtle_implementation incomplete = fixture;
    incomplete.query = NULL;
    if (turtle_endpoint_main(&incomplete, 4, args) != 1 || prepares != 0) return 1;
    return turtle_endpoint_main(&fixture, 4, args) == 0 &&
           prepares == 1 && releases == 1 ? 0 : 1;
}
