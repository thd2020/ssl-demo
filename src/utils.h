#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

bool gen_key();
int is_root();
void show_certs(SSL* ssl);
SSL_CTX* init_ctx(void);

#endif /* UTILS_H */