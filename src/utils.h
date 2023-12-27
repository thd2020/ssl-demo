#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>

RSA* gen_key();
char* gen_csr(RSA* r);
char* gen_crt(RSA* r);
int is_root();
void show_certs(SSL* ssl);
SSL_CTX* init_ctx(void);

#endif /* UTILS_H */