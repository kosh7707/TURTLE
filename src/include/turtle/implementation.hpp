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

typedef struct {
  turtle_role role;
  turtle_auth auth;
  const char *ca_file;
  const char *cert_file;
  const char *key_file;
  const char *server_name;
} turtle_tls_config;

typedef void (*turtle_io_hook)(void *, const unsigned char *, size_t);
typedef struct {
  void *context;
  turtle_io_hook before_send;
  turtle_io_hook after_recv;
} turtle_transport_hooks;

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
