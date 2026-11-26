#include <turtle/implementation.hpp>

// Starter only: these seven functions match the public ABI but never perform TLS.
// Include your TLS library here. Define struct turtle_tls to own its per-connection
// state. The framework owns connected_fd; use config's role, keys and trust policy.
turtle_tls *turtle_tls_setup(const turtle_tls_config * /*config*/, int /*connected_fd*/) {
    return nullptr;
}

void turtle_tls_free(turtle_tls * /*tls*/) {}

// Attach the supplied callbacks to the real encrypted transport; do not fabricate events.
turtle_status turtle_tls_set_hooks(turtle_tls * /*tls*/, const turtle_transport_hooks * /*hooks*/) {
    return TURTLE_TLS_UNSUPPORTED;
}

turtle_status turtle_tls_connect(turtle_tls * /*tls*/) {
    return TURTLE_TLS_UNSUPPORTED;
}

// Honor a requested server greeting at the point described in docs/submission.md.
turtle_status turtle_tls_accept(turtle_tls * /*tls*/, const unsigned char * /*greeting*/,
                               size_t /*greeting_len*/) {
    return TURTLE_TLS_UNSUPPORTED;
}

ptrdiff_t turtle_app_send(turtle_tls * /*tls*/, const unsigned char * /*data*/, size_t /*len*/) {
    return -1;
}

ptrdiff_t turtle_app_recv(turtle_tls * /*tls*/, unsigned char * /*data*/, size_t /*capacity*/) {
    return -1;
}
