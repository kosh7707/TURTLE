/* Only the source contract is needed. The padding extension changes actual ClientHello bytes. */
#include <turtle/implementation.h>
#include <string.h>

turtle_implementation turtle_openssl_base(void);
turtle_progress turtle_openssl_assemble(turtle_connection*, unsigned, size_t, turtle_buffer);
static turtle_progress padded(turtle_connection* c, unsigned type, size_t offset,
                              turtle_buffer out) {
    turtle_progress p = turtle_openssl_assemble(c, type, offset, out);
    if (type != TURTLE_CLIENT_HELLO || offset || p.status != TURTLE_DONE || p.produced < 40 ||
        out.size - p.produced < 20)
        return p;
    size_t at = 4 + 2 + 32;
    at += 1 + out.data[at];
    if (at + 2 > p.produced)
        return p;
    size_t suites = ((size_t)out.data[at] << 8) | out.data[at + 1];
    at += 2 + suites;
    if (at >= p.produced)
        return p;
    at += 1 + out.data[at];
    if (at + 2 > p.produced)
        return p;
    size_t ext = ((size_t)out.data[at] << 8) | out.data[at + 1];
    if (at + 2 + ext != p.produced)
        return p;
    /* Extension 21 (padding), 16 zero bytes; transcript commit receives these exact bytes. */
    memset(out.data + p.produced, 0, 20);
    out.data[p.produced + 1] = 21;
    out.data[p.produced + 3] = 16;
    p.produced += 20;
    ext += 20;
    out.data[at] = (unsigned char)(ext >> 8);
    out.data[at + 1] = (unsigned char)ext;
    size_t body = p.produced - 4;
    out.data[1] = (unsigned char)(body >> 16);
    out.data[2] = (unsigned char)(body >> 8);
    out.data[3] = (unsigned char)body;
    return p;
}
turtle_implementation turtle_register(void) {
    turtle_implementation api = turtle_openssl_base();
    api.assemble = padded;
    return api;
}
