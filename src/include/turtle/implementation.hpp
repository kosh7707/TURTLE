#ifndef TURTLE_IMPLEMENTATION_HPP
#define TURTLE_IMPLEMENTATION_HPP

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct turtle_tls turtle_tls;
typedef enum { TURTLE_CLIENT, TURTLE_SERVER } turtle_role;
typedef enum { TURTLE_SERVER_AUTH, TURTLE_MUTUAL_AUTH } turtle_auth;
typedef enum {
  TURTLE_TLS_OK,
  TURTLE_TLS_UNSUPPORTED,
  TURTLE_TLS_ERROR
} turtle_status;

/* Each field is 1 (yes), 0 (no), or -1 (not known). Required authentication
 * must succeed before a bridge returns TURTLE_TLS_OK from connect/accept. */
typedef struct {
  int tls13;
  int resumed;
  int early_data;
  int peer_cert_present;
  int peer_verified;
} turtle_session_info;

typedef struct {
  turtle_role role;
  turtle_auth auth;
  const char *ca_file;
  const char *cert_file;
  const char *key_file;
  const char *server_name;
  void *context;
  /* Report actual session facts when the local handshake has succeeded. */
  void (*report_session)(void *context, const turtle_session_info *info);
  /* Report greeting bytes accepted after sending server Finished and before
   * waiting for client Finished. Call once per positive native write, in order. */
  void (*greeting_written)(void *context, const unsigned char *bytes, size_t size);
} turtle_tls_config;

typedef void (*turtle_io_hook)(void *, const unsigned char *, size_t);
typedef struct {
  void *context;
  turtle_io_hook before_send;
  turtle_io_hook after_recv;
  /* Use this trio on the same connection thread as TLS. Coverage starts at
   * hook install (active=1), ends on detach (active=0), or is marked incomplete
   * (active=-1). Pair every real encrypted transport call; report the native
   * result (positive byte count, zero for no transfer/EOF, negative on error).
   * The two one-sided callbacks above are retained for source compatibility;
   * they do not supply paired transfer evidence. */
  void (*coverage)(void *context, int active);
  void (*transfer_begin)(void *context, int sent, size_t requested);
  void (*transfer_end)(void *context, int sent, size_t requested,
                       ptrdiff_t result, const unsigned char *bytes);
} turtle_transport_hooks;

/* Prepare the session only. Neither setup nor hook installation may send or
 * receive TLS bytes, start a handshake, or report a completed session. */
turtle_tls *turtle_tls_setup(const turtle_tls_config *config, int connected_fd);
void turtle_tls_free(turtle_tls *tls);
turtle_status turtle_tls_set_hooks(turtle_tls *tls,
                                   const turtle_transport_hooks *hooks);
turtle_status turtle_tls_connect(turtle_tls *tls);
turtle_status turtle_tls_accept(turtle_tls *tls, const unsigned char *greeting,
                                size_t greeting_len);
ptrdiff_t turtle_app_send(turtle_tls *tls, const unsigned char *data,
                          size_t len);
ptrdiff_t turtle_app_recv(turtle_tls *tls, unsigned char *data,
                          size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
