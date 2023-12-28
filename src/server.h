#ifndef SERVER_H
#define SERVER_H

#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <resolv.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1
#define BUFFER  1024

int server(int port, int listnum, char* cert_path, char* key_path);
int start_listening(int port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void servlet(SSL* ssl);

#endif /* SERVER_H */