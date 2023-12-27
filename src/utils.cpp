#include "utils.h"

/** 生成公钥私钥 */
RSA* gen_key(){
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
    return(r);
}

/** 生成证书签名请求csr*/
char* gen_csr(RSA* r){
    EVP_PKEY* pkey;
    X509* x509 = NULL;
    X509_NAME* subject = NULL,* name = NULL;
    BIO* bio = NULL;
    X509_REQ* x509Req = NULL;
    char* szCSR = NULL;

    pkey = EVP_PKEY_new();
    x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    EVP_PKEY_assign_RSA(pkey, r);
    X509_set_pubkey(x509, pkey);
    /** set the properties of the cert */
    name = X509_get_subject_name(x509);
    subject = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                            (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                            (unsigned char *)"thd2020 Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                            (unsigned char *)"thd2020", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, SN_countryName, MBSTRING_UTF8,
                            (unsigned char *)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, SN_stateOrProvinceName, MBSTRING_UTF8,
                            (unsigned char *)"SiChuan", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, SN_localityName,  MBSTRING_UTF8,
                            (unsigned char *)"ChengDu", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_set_subject_name(x509, subject);
    x509Req = X509_to_X509_REQ(x509, pkey, EVP_md5());
    if(!x509Req)
    {
        goto free_all;
    }
    // 可视化输出
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(bio, x509Req);
    szCSR = (char*)malloc(sizeof(bio));
    if(!szCSR)
    {
        goto free_all;
    }
    memset(szCSR, 0, sizeof(bio));
    BIO_read(bio, szCSR, sizeof(bio));
    return(szCSR);
    free_all:
        if(x509)
            X509_free(x509);
        if(x509Req)
            X509_REQ_free(x509Req);
        if(bio)
            BIO_free(bio);
        if(szCSR)
            free(szCSR);
}

char* gen_crt(RSA* r){
    EVP_PKEY* pkey;
    X509* x509 = NULL;
    X509_NAME* subject = NULL,* name = NULL;
    BIO* bio = NULL;
    X509_REQ* x509Req = NULL;
    char* szCSR = NULL;

    pkey = EVP_PKEY_new();
    x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    EVP_PKEY_assign_RSA(pkey, r);
    X509_set_pubkey(x509, pkey);
    /** set the properties of the cert */
    name = X509_get_subject_name(x509);
    subject = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                            (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                            (unsigned char *)"thd2020 Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                            (unsigned char *)"thd2020", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, SN_countryName, MBSTRING_UTF8,
                            (unsigned char *)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, SN_stateOrProvinceName, MBSTRING_UTF8,
                            (unsigned char *)"SiChuan", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, SN_localityName,  MBSTRING_UTF8,
                            (unsigned char *)"ChengDu", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_set_subject_name(x509, subject);
    /** sign the cert */
    X509_sign(x509, pkey, EVP_sha1());
    /** write the cert to disk */
    FILE* f = fopen("cert.pem", "wb");
    PEM_write_X509(
        f,
        x509
    );
    free_all:
        if(x509)
            X509_free(x509);
        if(x509Req)
            X509_REQ_free(x509Req);
        if(bio)
            BIO_free(bio);
        if(szCSR)
            free(szCSR);
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
    X509* cert;
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