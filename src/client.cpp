#include "client.h"
#include "utils.h"
#define NUM_PKEYS 1
#define DEAL_ERR(lab)\
    ERR_print_errors_fp(stderr);\
    fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);\
    goto lab;

int client(char* hostname, int portnum){
    SSL_CTX* ctx;
    int server;
    SSL* ssl;
    unsigned char* buf = (unsigned char*)malloc(BUFFER);
    char input[BUFFER];
    int bytes;
    pid_t cpid;
    int ret = 0;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char* iv = (unsigned char*)malloc(16);
    unsigned char* ek[NUM_PKEYS];
    int ekl[NUM_PKEYS];
    unsigned char* cbuf = (unsigned char*)malloc(BUFFER);
    unsigned char* mbuf = (unsigned char*)malloc(BUFFER);
    unsigned char *p;
    int len, clen, mlen, i;
    BIO *out = NULL;
    EVP_PKEY* mpkey = NULL;
    EVP_PKEY* pkey[NUM_PKEYS];
    X509* server_cert;
    FILE* cert_file;
    FILE* pkey_file;

    SSL_library_init();
    ctx = init_client_ctx();
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL)<=0){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    server = open_connection(hostname, portnum);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);
    if (SSL_connect(ssl) <= 0){
        int ret = 0;
        SSL_get_error(ssl, ret);
        ERR_print_errors_fp(stderr);
    }
    else{
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        show_certs(ssl);
        //server_cert = SSL_get_peer_certificate(ssl);
        //mpkey = X509_get_pubkey(server_cert);
        pkey_file = fopen("private.pem", "rb");
        mpkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
        if (!(cctx = EVP_CIPHER_CTX_new())) {DEAL_ERR(end);}
        pkey[0] = mpkey;
        SSL_read(ssl, ek[0], 256);
        ekl[0] = 256;
        SSL_read(ssl, iv, EVP_CIPHER_get_iv_length(EVP_sm4_cbc()));
        if (!EVP_OpenInit(cctx, EVP_sm4_cbc(), ek[0], ekl[0], iv, pkey[0])) {DEAL_ERR(end);}
        cpid = fork();
        if (cpid == 0){
            while(1){
                printf("\nMessage to server:");
                fgets(input, BUFFER, stdin);
                SSL_write(ssl, input, strlen(input));
            }
        }
        else{
            while(1){
                bytes = SSL_read(ssl, buf, BUFFER);
                if (bytes > 0){
                    if (!EVP_OpenUpdate(cctx, mbuf, &len, buf, lengthOfU(buf))) {DEAL_ERR(end);}
                    if (!EVP_OpenFinal(cctx, mbuf, &len)) {DEAL_ERR(end);}
                    printf("\nMessage from server: %s\nAfter decrypt: %s\n", buf, p);
                }
            }
        }
        end:
            EVP_CIPHER_CTX_free(cctx);
            for (i = 0; i < NUM_PKEYS; i++) {
                EVP_PKEY_free(pkey[i]);
                OPENSSL_free(ek[i]);
            }
        SSL_free(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}

int open_connection(char* hostname, int port){
    int server;
    struct hostent* host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL){
        fprintf(stderr, "cannot resolve hostname %s\n", hostname);
        abort();
    }
    server = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if (connect(server, (struct sockaddr*)&addr, sizeof(addr)) != 0){
        close(server);
        fprintf(stderr, "cannot connect to server %s:%s\n", hostname, strerror(errno));
        abort();
    }
    return server;
}