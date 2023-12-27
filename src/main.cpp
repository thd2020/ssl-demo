#include <iostream>
#include <stdlib.h>
#include "utils.h"
#include "server.h"
#include "client.h"

int main(int argc, char** argv){
    if (strcmp(argv[1], "--gen-cert") == 0 || strcmp(argv[1], "-g") == 0){
        RSA* r = gen_key();
        gen_crt(r);
    }
    else if (strcmp(argv[1], "--server") == 0 || strcmp(argv[1], "-s") == 0){
        if (argc == 3){
            server(atoi(argv[2]), 10, "cert.pem", "private.pem");
        }
        else if (argc == 2){
            server(3000, 10, "cert.pem", "private.pem");
        }
        else if (argc == 5){
            server(atoi(argv[2]), 10, argv[3], argv[4]);
        }
        else{
            printf("Usage: --server/-s {port(63510)} {cert_path} {key_path}");
        }
    }
    else if (strcmp(argv[1], "--client") == 0 || strcmp(argv[1], "-c") == 0){
        if (argc == 4){
            client(argv[2], atoi(argv[3]));
        }
        else{
            printf("Usage: --client/-c hostname port");
        }
    }
    else{
        printf("Unrecognized command, usage:\n --gen-key/-g\n--server/-s {port(63510)} {cert_path} {key_path}\n--client/-c hostname port");
    }
    return 0;
}