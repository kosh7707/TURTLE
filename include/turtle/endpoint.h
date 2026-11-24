#ifndef TURTLE_ENDPOINT_H
#define TURTLE_ENDPOINT_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  TURTLE_OK = 0,
  TURTLE_CLOSED,
  TURTLE_UNSUPPORTED,
  TURTLE_ERROR
} turtle_result;

typedef enum {
  TURTLE_LOCAL_COMPLETE,
  TURTLE_SERVER_CAN_SEND
} turtle_hs_point;

/* One fresh, prepared role connection before its first TLS operation. The
 * caller owns conn (opaque), TLS configuration, transport and any wire hooks.
 * Callbacks run synchronously; handle native retry/wait inside the callback.
 * No callback retains a supplied buffer or throws across this C boundary. */
typedef struct turtle_endpoint {
  void *conn;
  /* LOCAL_COMPLETE: confirm local full-handshake success. SERVER_CAN_SEND:
   * server Finished sent, application write possible without waiting for
   * client Finished. Return UNSUPPORTED if that opportunity is unavailable. */
  turtle_result (*handshake_until)(void *conn, turtle_hs_point goal);
  /* At SERVER_CAN_SEND, use the actual early server write path. Do not defer
   * the write to local completion. OK: 0 < *accepted <= len. */
  turtle_result (*write_plain)(void *conn, turtle_hs_point at, const void *buf,
                               size_t len, size_t *accepted);
  /* Ordinary app plaintext read; may be the first TLS operation. Do not
   * wait to fill the buffer. OK: 0 < *received <= capacity. */
  turtle_result (*read_plain)(void *conn, void *buf, size_t capacity,
                              size_t *received);
} turtle_endpoint;

/* Called once in a TURTLE-launched role process. Borrows endpoint and conn
 * only until return. Only callbacks used by the selected role/scenario need
 * to be supplied. CLOSED means peer EOF before the task finished; an absent
 * required operation means UNSUPPORTED. Failure never consumes a byte count.
 * SDK owns scenario sequencing, benchmark plaintext checks and timestamps. */
turtle_result turtle_run_endpoint(const turtle_endpoint *endpoint);

#ifdef __cplusplus
}
#endif
#endif
