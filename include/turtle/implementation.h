#ifndef TURTLE_IMPLEMENTATION_H
#define TURTLE_IMPLEMENTATION_H

/* Source contract: compile this header and implementation together. No binary ABI. */
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct turtle_context turtle_context;
typedef struct turtle_connection turtle_connection;
typedef struct {
    const uint8_t* data;
    size_t size;
} turtle_bytes;
typedef struct {
    uint8_t* data;
    size_t size;
} turtle_buffer;
typedef enum { TURTLE_CLIENT, TURTLE_SERVER } turtle_role;
typedef enum { TURTLE_MORE, TURTLE_DONE, TURTLE_ERROR } turtle_status;
typedef struct {
    turtle_status status;
    size_t consumed;
    size_t produced;
    int error;
} turtle_progress;
typedef enum {
    TURTLE_BEGIN,           /* Connection protocol initialization. No message or I/O. */
    TURTLE_PREPARE_SEND,    /* Select exactly the specified message; pre-work. */
    TURTLE_COMMIT_SEND,     /* Transcript/post-work after complete assembly. See ordering below. */
    TURTLE_PREPARE_RECEIVE, /* Transcript/pre-work on one reassembled message. */
    TURTLE_COMMIT_RECEIVE,  /* Post-processing and key transitions. */
    TURTLE_FINISH           /* Local handshake finalization. */
} turtle_transition;
enum {
    TURTLE_CLIENT_HELLO = 1,
    TURTLE_SERVER_HELLO = 2,
    TURTLE_ENCRYPTED_EXTENSIONS = 8,
    TURTLE_CERTIFICATE = 11,
    TURTLE_CERTIFICATE_REQUEST = 13,
    TURTLE_CERTIFICATE_VERIFY = 15,
    TURTLE_FINISHED = 20,
    TURTLE_APPLICATION = 256
};
typedef struct {
    turtle_role role;
    int mutual_auth;
    const char* ca_file;
    const char* certificate_file;
    const char* private_key_file;
    const char* server_name;
    const char* group;
    size_t max_message;
} turtle_options;
typedef struct {
    const char* name;
    const char* source;
    const char* technique;
} turtle_support;
typedef struct {
    int full_handshake;
    int peer_verified;
    int peer_certificate;
    int technique_used;
    uint64_t keygen, encapsulate, decapsulate, optimized;
    unsigned certificate_cache_hit, request_cache_hit, ssc_cache_hit;
} turtle_result;

typedef struct {
    /* Inventory availability bits: message buffer=1, record buffers=2, technique cache=4.
     * Requested storage, excluding allocator overhead, certificates, stacks and global runtime. */
    unsigned storage_available;
    uint64_t message_buffer_bytes, record_buffer_bytes, cache_bytes;
} turtle_storage;

/* There are no sockets, network callbacks, clocks or measurement sinks here.
 * All byte views are borrowed for the duration of a call. Creation transfers
 * ownership to the caller, which must use the matching destroy function.
 * assemble/process operate only on the message selected by transition.
 * MORE requires positive progress. A completed operation is never retried.
 * COMMIT_SEND advances the transcript before assembling the next message.
 * A bundled record may still contain unprotected bytes at this point. Before
 * a Hello/Finished commit changes protection keys, the framework protects all
 * pending bytes with the previous keys. Socket submission is independent.
 * protect/unprotect handle exactly one record, including its 5-byte header.
 * Partial socket writes must reuse the already protected output unchanged.
 */
typedef struct turtle_implementation {
    turtle_support (*support)(void);
    turtle_context* (*create_context)(const turtle_options*, char*, size_t);
    void (*destroy_context)(turtle_context*);
    turtle_connection* (*create_connection)(turtle_context*, char*, size_t);
    void (*destroy_connection)(turtle_connection*);
    int (*transition)(turtle_connection*, turtle_transition, unsigned, turtle_bytes);
    turtle_progress (*assemble)(turtle_connection*, unsigned, size_t, turtle_buffer);
    turtle_progress (*process)(turtle_connection*, unsigned, turtle_bytes, int);
    turtle_progress (*protect)(turtle_connection*, unsigned, turtle_bytes, turtle_buffer);
    turtle_progress (*unprotect)(turtle_connection*, turtle_bytes, turtle_buffer, unsigned*);
    turtle_result (*result)(const turtle_connection*);
    turtle_storage (*storage)(const turtle_connection*); /* Snapshot after the measured scenario. */
    const char* (*error)(const turtle_connection*);
} turtle_implementation;

/* Each executable links exactly one definition. Researchers may return a copy
 * of a base table with just assemble replaced for ClientHello experiments. */
turtle_implementation turtle_register(void);
#ifdef __cplusplus
}
#endif
#endif
