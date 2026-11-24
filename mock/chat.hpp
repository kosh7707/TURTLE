#pragma once

#include <openssl/types.h>

// Takes a handshaken, socket-backed TLS connection. The caller retains ownership.
void run_chat(SSL *ssl);
