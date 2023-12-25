#include "utils.h"

bool gen_key(){
    int ret = 0;
    RSA* r = NULL;
    BIGNUM* bne = NULL; /*big number*/
    BIO* bp_public = NULL,* bp_private = NULL;
    int bits = 2048;
    unsigned long e = RSA_F4;

    /**generate rsa key*/
    bne = BN_new(); /*gen big number*/
    ret = BN_set_word(bne, e); /*assign e to big number*/
    if (ret != 1){
        goto free_all;
    }
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1){
        goto free_all;
    }
    /**save public key*/
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if (ret != 1){
        goto free_all;
    }
    /**save private key*/
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    /**free_all_resource*/
    free_all:
        BIO_free_all(bp_public);/*free public key*/
        BIO_free_all(bp_private);/*free private key*/
        RSA_free(r);/*free RSA*/
    return(ret == 1);
}

int is_root(){
    if (getuid() != 0){
        return 0;
    }
    else {
        return 1;
    }
}

/**show certs to client*/
void show_certs(SSL* ssl){
    X509 *cert;
    char* line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL){
        printf("certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Server: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Client: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else{
        printf("No Certificates.\n");
    }
}


SSL_CTX* init_ctx(void){
    const SSL_METHOD* method;
    SSL_CTX* ctx; /*SSL握手前的环境准备，CA文件和目录，证书文件和私钥，协议版本*/

    OpenSSL_add_all_algorithms(); /* load and register all cryptos*/
    SSL_load_error_strings();
    method = TLSv1_2_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}