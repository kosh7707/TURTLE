/* Test-only independent TLS app. Wire-only observation is opt-in.
 * The three callbacks have no scenario names, benchmark payloads or timers. */
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <turtle/endpoint.h>
#include <turtle/observe.h>
#include <unistd.h>

static void check(int ok, const char *what) {
  if (!ok) {
    fprintf(stderr, "test consumer: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
  }
}
static int connected_socket(int server, const char *host, const char *port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr = {.sin_family = AF_INET,
                             .sin_port = htons((uint16_t)strtoul(port, NULL, 10))};
  check(fd >= 0 && inet_pton(AF_INET, host, &addr.sin_addr) == 1, "socket");
  if (!server) {
    check(connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0, "connect");
    return fd;
  }
  check(bind(fd, (struct sockaddr *)&addr, sizeof addr) == 0 &&
            listen(fd, 1) == 0, "listen");
  int peer = accept(fd, NULL, NULL);
  close(fd);
  check(peer >= 0, "accept");
  return peer;
}
/* This test connection is single-threaded and its socket BIO is non-recursive. */
static long wire(BIO *bio, int op, const char *buf, size_t size, int argi,
                 long argl, int ret, size_t *done) {
  (void)argi;
  (void)argl;
  int kind = op & ~BIO_CB_RETURN;
  if (kind != BIO_CB_READ && kind != BIO_CB_WRITE)
    return ret;
  int sent = kind == BIO_CB_WRITE;
  turtle_observe_stamp *begins = (void *)BIO_get_callback_arg(bio);
  if (op & BIO_CB_RETURN)
    turtle_observe_io(begins[sent], turtle_observe_now(), "library_io", sent,
                      size, ret > 0 && done ? (int64_t)*done : ret, buf, 0);
  else
    begins[sent] = turtle_observe_now();
  return ret;
}
static turtle_result handshake(void *ssl, turtle_hs_point goal) {
  if (goal == TURTLE_LOCAL_COMPLETE)
    return SSL_do_handshake(ssl) == 1 && SSL_is_init_finished(ssl)
               ? TURTLE_OK : TURTLE_ERROR;
  size_t n = 0;
  char scratch;
  if (SSL_read_early_data(ssl, &scratch, 1, &n) != SSL_READ_EARLY_DATA_FINISH || n)
    return TURTLE_ERROR;
  return SSL_is_init_finished(ssl) ? TURTLE_UNSUPPORTED : TURTLE_OK;
}
static turtle_result write_plain(void *ssl, turtle_hs_point at, const void *buf,
                                 size_t size, size_t *n) {
  size_t offer = size > 2 ? 2 : size; /* force real partial results */
  int rc = at == TURTLE_SERVER_CAN_SEND ? SSL_write_early_data(ssl, buf, offer, n)
                                        : SSL_write_ex(ssl, buf, offer, n);
  return rc == 1 ? TURTLE_OK : TURTLE_ERROR;
}
static turtle_result read_plain(void *ssl, void *buf, size_t cap, size_t *n) {
  ERR_clear_error();
  int rc = SSL_read_ex(ssl, buf, cap > 2 ? 2 : cap, n);
  if (rc == 1)
    return TURTLE_OK;
  return SSL_get_error(ssl, rc) == SSL_ERROR_ZERO_RETURN ? TURTLE_CLOSED : TURTLE_ERROR;
}
int main(int argc, char **argv) {
  int with_wire = argc == 9 && strcmp(argv[8], "--wire") == 0;
  check(argc == 8 || with_wire, "expected ROLE HOST PORT CA CERT KEY PEER_NAME [--wire]");
  signal(SIGPIPE, SIG_IGN);
  int server = strcmp(argv[1], "server") == 0;
  int verify = *argv[7] != '\0';
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  check(ctx && SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) &&
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) &&
            SSL_CTX_set1_groups_list(ctx, "X25519") && SSL_CTX_set_num_tickets(ctx, 0),
        "configure TLS 1.3");
  if (*argv[5])
    check(SSL_CTX_use_certificate_chain_file(ctx, argv[5]) == 1 &&
              SSL_CTX_use_PrivateKey_file(ctx, argv[6], SSL_FILETYPE_PEM) == 1,
          "certificate and key");
  if (verify) {
    check(SSL_CTX_load_verify_locations(ctx, argv[4], NULL) == 1, "CA");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
                                (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);
  }
  SSL *ssl = SSL_new(ctx);
  check(ssl != NULL, "TLS session");
  if (verify) {
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    check(SSL_set1_host(ssl, argv[7]) == 1, "expected peer");
  }
  if (server)
    SSL_set_accept_state(ssl);
  else
    SSL_set_connect_state(ssl);
  int fd = connected_socket(server, argv[2], argv[3]);
  check(SSL_set_fd(ssl, fd) == 1, "transport");
  turtle_observe_stamp calls[2];
  BIO *bio = SSL_get_rbio(ssl);
  if (with_wire) {
    check(bio && bio == SSL_get_wbio(ssl), "shared socket BIO");
    BIO_set_callback_arg(bio, (char *)calls);
    BIO_set_callback_ex(bio, wire);
    turtle_observe_coverage("library_io", 1);
  }
  const turtle_endpoint endpoint = {ssl, handshake, write_plain, read_plain};
  turtle_result r = turtle_run_endpoint(&endpoint);
  if (with_wire) {
    BIO_set_callback_ex(bio, NULL);
    turtle_observe_coverage("library_io", 0);
  }
  if (r == TURTLE_OK)
    SSL_shutdown(ssl);
  else
    ERR_print_errors_fp(stderr);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(fd);
  return r == TURTLE_OK ? 0 : 1;
}
