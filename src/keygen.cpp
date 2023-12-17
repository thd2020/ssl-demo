#include "keygen.h"

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