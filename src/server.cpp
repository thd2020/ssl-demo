#include <server.h>
#include "utils.h"
#define DEAL_ERR(lab)\
        fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);\
        goto lab;
#define NUM_PKEYS 1

int server(int port, int listnum, char* cert_path, char* key_path){
    int lis_so, con_so;
    struct sockaddr_in my_addr, their_addr;
    socklen_t len = sizeof(my_addr);
    unsigned int myport, lisnum;
    char buf[BUFFER + 1];
    SSL_CTX* ctx;
    SSL** ssls = (SSL**)malloc(512);
    unsigned char* p;

    if(!is_root())        /* if root user is not executing server report must be root user */
	{
	printf("This program must be run as root/sudo user!!\n");
	exit(0);
	}
    SSL_library_init();
    ctx = init_server_ctx();
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /**设置信任根证书*/
    if (SSL_CTX_load_verify_locations(ctx, cert_path, NULL)<=0){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /** 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /** 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /** 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)){
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    lis_so = start_listening(port);
    while (1){
    con_so = accept(lis_so, (struct sockaddr*)&their_addr, &len);
    SSL* ssl = *(ssls+1);
    printf("Connection from:%s:%d\n", inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, con_so);
    std::thread task(servlet, ssl);
    task.detach();
    }
    SSL_CTX_free(ctx);
}

int start_listening(int port){
    int lis_so; /*listening socket file descriptor*/
    struct sockaddr_in addr;

    lis_so = socket(PF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;/*三件套*/
    /**绑定*/
    if (bind(lis_so, (struct sockaddr*)&addr, sizeof(addr)) != 0){
        fprintf(stderr, "can't bind port %d: %s\n", port, strerror(errno));
        abort();
    }
    /**监听*/
    if (listen(lis_so, 10) != 0){
        fprintf(stderr, "listen on port %d failed: %s\n", port, errno);
        abort();
    }
    printf("server is now listening on port %d\n", port);
    return lis_so;
}

void load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile){
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM)){
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        abort();
    }
    /**verify private key*/
    if (!SSL_CTX_check_private_key(ctx)){
        fprintf(stderr, "Private key not match public Cert\n");
        abort();
    }
}


/**threadable serve the connection*/
void servlet(SSL* ssl){
    char buf[BUFFER];
    char* input = (char*)malloc(BUFFER);
    int con_so, bytes;
    pid_t cpid;
    int ret = 0;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_get_iv_length(EVP_sm4_cbc()));
    unsigned char *ek[NUM_PKEYS] = {0};
    int ekl[NUM_PKEYS];
    unsigned char* cbuf = (unsigned char*)malloc(BUFFER);
    unsigned char* mbuf = (unsigned char*)malloc(BUFFER);
    unsigned char* p = (unsigned char*)malloc(BUFFER);
    int len, clen, mlen, i;
    BIO *out = NULL;
    EVP_PKEY* mpkey = NULL;
    EVP_PKEY* pkey[NUM_PKEYS];
    X509* server_cert;
    FILE* cert_file,* pkey_file;

    if (SSL_accept(ssl) <= 0)
        ERR_print_errors_fp(stderr);
    else{
        show_certs(ssl);
        /**数字信封*/
        pkey_file = fopen("public.pem", "rb");
        mpkey = PEM_read_PUBKEY(pkey_file, NULL, NULL, NULL);
        pkey[0] = mpkey;
        if (!(cctx = EVP_CIPHER_CTX_new())) {DEAL_ERR(end);}
        for (i = 0; i < NUM_PKEYS; i++) {
            ekl[i] = EVP_PKEY_get_size(pkey[i]);
            ek[i] = (unsigned char*)OPENSSL_malloc(ekl[i]);
        }
        if (i = EVP_SealInit(cctx, EVP_sm4_cbc(), ek, ekl, iv, pkey, NUM_PKEYS) != NUM_PKEYS) {DEAL_ERR(end);}
        SSL_write(ssl, ek[0], 256);
        sleep(1);
        SSL_write(ssl, iv, EVP_CIPHER_get_iv_length(EVP_sm4_cbc()));
        cpid = fork();
        if (cpid == 0){ /*子进程*/
            while(1){
                bytes = SSL_read(ssl, buf, sizeof(buf));
                if (bytes > 0){
                    buf[bytes] = 0;
                    printf("\nMESSAGE FROM CLIENT: %s\n", buf);
                }
                else
                    ERR_print_errors_fp(stderr);
            }
        }
        else{
            while(1){
                printf("\nMESSAGE TO CLIENT:");
                fgets(input, BUFFER, stdin);
                if (!EVP_SealUpdate(cctx, p, &len, (unsigned char*)input, strlen(input))) {DEAL_ERR(end);}
                if (!EVP_SealFinal(cctx, p, &len)) {DEAL_ERR(end);}
                SSL_write(ssl, p, len);
            }
        }
    }
    end:
        EVP_CIPHER_CTX_free(cctx);
        for (i = 0; i < NUM_PKEYS; i++) {
            EVP_PKEY_free(pkey[i]);
            OPENSSL_free(ek[i]);
        }
    con_so = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(con_so);
    return;
}