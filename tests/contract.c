#include <turtle/implementation.h>
/* Compile the implementer contract as C, without framework or C++ headers. */
_Static_assert(TURTLE_APPLICATION > 255, "logical application type does not alias handshake types");
int turtle_contract_c(turtle_progress p) {
    return p.status == TURTLE_DONE;
}
