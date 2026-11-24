#ifndef TURTLE_IO_BOUNDARY_H
#define TURTLE_IO_BOUNDARY_H

/* TURTLE supplies these callbacks. Invoke them synchronously at the TLS/transport
 * boundary: once before each lower send attempt (even if it fails), and once
 * immediately after a receive returns data (never for EOF, errors or retries
 * that produced no bytes). Neither callback represents a TLS record. */
typedef struct turtle_io_hooks {
    void *context;
    void (*before_send)(void *context);
    void (*after_receive)(void *context);
} turtle_io_hooks;

/* The implementation supplies this registration point for one transport.
 * Copy the hook values; an all-zero set detaches. Install/detach while idle. */
typedef struct turtle_io_boundary {
    void *transport;
    void (*set_hooks)(void *transport, turtle_io_hooks hooks);
} turtle_io_boundary;

#endif
