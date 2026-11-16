#pragma once
#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
int ssl_prepare_client_hello(mbedtls_ssl_context* ssl);
int ssl_write_client_hello_body(mbedtls_ssl_context* ssl, unsigned char* buf, unsigned char* end,
                                size_t* out_len, size_t* binders_len);
int ssl_tls13_parse_server_hello(mbedtls_ssl_context* ssl, const unsigned char* buf,
                                 const unsigned char* end, int is_hrr);
int ssl_tls13_postprocess_server_hello(mbedtls_ssl_context* ssl);
int ssl_tls13_parse_encrypted_extensions(mbedtls_ssl_context* ssl, const unsigned char* buf,
                                         const unsigned char* end);
int ssl_tls13_parse_certificate_request(mbedtls_ssl_context* ssl, const unsigned char* buf,
                                        const unsigned char* end);
int ssl_tls13_parse_client_hello(mbedtls_ssl_context* ssl, const unsigned char* buf,
                                 const unsigned char* end, int turtle_transcript);
int ssl_tls13_postprocess_client_hello(mbedtls_ssl_context* ssl, int hrr_required);
int ssl_tls13_prepare_server_hello(mbedtls_ssl_context* ssl);
int ssl_tls13_write_server_hello_body(mbedtls_ssl_context* ssl, unsigned char* buf,
                                      unsigned char* end, size_t* out_len, int is_hrr);
int ssl_tls13_finalize_server_hello(mbedtls_ssl_context* ssl);
int ssl_tls13_write_encrypted_extensions_body(mbedtls_ssl_context* ssl, unsigned char* buf,
                                              unsigned char* end, size_t* out_len);
int ssl_tls13_write_certificate_request_body(mbedtls_ssl_context* ssl, unsigned char* buf,
                                             const unsigned char* end, size_t* out_len);
int ssl_tls13_parse_certificate_verify(mbedtls_ssl_context* ssl, const unsigned char* buf,
                                       const unsigned char* end, const unsigned char* verify_buffer,
                                       size_t verify_buffer_len);
void ssl_tls13_create_verify_structure(const unsigned char* transcript_hash,
                                       size_t transcript_hash_len, unsigned char* verify_buffer,
                                       size_t* verify_buffer_len, int from);
int ssl_tls13_validate_certificate(mbedtls_ssl_context* ssl);
int ssl_tls13_write_certificate_body(mbedtls_ssl_context* ssl, unsigned char* buf,
                                     unsigned char* end, size_t* out_len);
int ssl_tls13_write_certificate_verify_body(mbedtls_ssl_context* ssl, unsigned char* buf,
                                            unsigned char* end, size_t* out_len);
int ssl_tls13_preprocess_finished_message(mbedtls_ssl_context* ssl);
int ssl_tls13_parse_finished_message(mbedtls_ssl_context* ssl, const unsigned char* buf,
                                     const unsigned char* end);
int ssl_tls13_write_finished_message_body(mbedtls_ssl_context* ssl, unsigned char* buf,
                                          unsigned char* end, size_t* out_len);

int mbedtls_ssl_tls13_parse_certificate(mbedtls_ssl_context*, const unsigned char*,
                                        const unsigned char*);
int ssl_tls13_prepare_finished_message(mbedtls_ssl_context*);
