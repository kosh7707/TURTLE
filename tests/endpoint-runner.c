/* Standalone C caller: knows three TLS operations, not the scenario. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <turtle/endpoint.h>
#include <turtle/observe.h>

struct connection {
  const char *input, *mode;
  size_t remaining;
  const char *next;
};

static turtle_result handshake(void *ctx, turtle_hs_point point) {
  const struct connection *c = ctx;
  fputc(point == TURTLE_LOCAL_COMPLETE ? 'H' : 'E', stderr);
  if (!strcmp(c->mode, "noearly") && point == TURTLE_SERVER_CAN_SEND)
    return TURTLE_UNSUPPORTED;
  return TURTLE_OK;
}
static turtle_result send_plain(void *ctx, turtle_hs_point at, const void *buf,
                                size_t len, size_t *accepted) {
  struct connection *c = ctx;
  fputc(at == TURTLE_LOCAL_COMPLETE ? 'W' : 'w', stderr);
  if (!strcmp(c->mode, "trickle")) {
    *accepted = len > 2 ? 2 : len;
    if (len != c->remaining || (c->next && c->next != buf) ||
        memcmp(c->input, buf, *accepted))
      return TURTLE_ERROR;
    c->input += *accepted;
    c->next = (const char *)buf + *accepted;
    c->remaining -= *accepted;
    return TURTLE_OK;
  }
  if (!strcmp(c->mode, "zero")) *accepted = 0;
  else if (!strcmp(c->mode, "overflow")) *accepted = len + 1;
  else *accepted = !strcmp(c->mode, "partial") && len > 2 ? 2 : len;
  return !strcmp(c->mode, "writeerror") ? TURTLE_ERROR : TURTLE_OK;
}
static turtle_result recv_plain(void *ctx, void *buf, size_t cap, size_t *n) {
  struct connection *c = ctx;
  size_t len = strlen(c->input);
  fputc('R', stderr);
  if (!strcmp(c->mode, "overflow")) { *n = cap + 1; return TURTLE_OK; }
  if (!strcmp(c->mode, "zero")) { *n = 0; return TURTLE_OK; }
  if (!len) return TURTLE_CLOSED;
  if (len > cap) len = cap;
  if (!strcmp(c->mode, "partial") && len > 2) len = 2;
  memcpy(buf,c->input,len);
  c->input += len;
  *n = len;
  return TURTLE_OK;
}
int main(int argc, char **argv) {
  if (argc != 3) return 99;
  struct connection c = {argv[1], argv[2], strlen(argv[1]), NULL};
  int tail = !strcmp(c.mode, "partial-tail");
  if (tail) c.mode = "partial";
  const turtle_endpoint ep = {
    &c, handshake,
    !strcmp(c.mode,"nouwrite") ? NULL : send_plain,
    !strcmp(c.mode,"nouread") ? NULL : recv_plain
  };
  int status = turtle_run_endpoint(&ep);
  if (tail) {
    for (int i = 0; i < 96; ++i)
      turtle_observe_fact("diagnostic", 0);
    turtle_observe_fact("endpoint_unsupported", 1);
    turtle_observe_flush();
    turtle_observe_flush(); // also followed by normal exit handling
  }
  return status;
}
