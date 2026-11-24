#include <turtle/role.h>
#include "../implementations/implementation.h"

/* Compile the smallest vendor-facing driver in either C or C++. The real
 * public calls and error translation live with the TLS object, not the SDK. */
extern int native_call(void *, turtle_action);
extern turtle_result translate(void *, int);
extern int finished_facts(void *, turtle_op, turtle_handshake_info *);
int drive(turtle_session *s, void *tls) {
    turtle_action a;
    while (turtle_pull(s, &a) == 1 && a.op != TURTLE_DONE) {
        turtle_handshake_info f;
        turtle_before(s);
        int rc = native_call(tls, a);
        turtle_returned(s);
        turtle_result r = translate(tls, rc);
        if (turtle_submit(s, r, finished_facts(tls, a.op, &f) ? &f : 0) != 1)
            break;
    }
    return turtle_session_close(s);
}
