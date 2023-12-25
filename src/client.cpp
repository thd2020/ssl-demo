#include "client.h"
#include "utils.h"

int client(char* hostname, int portnum){
    SSL_CTX* ctx;
    int server;
    SSL* ssl;
    char buf[BUFFER];
    char input[BUFFER];
    int bytes;
    pid_t cpid;

    SSL_library_init();
    ctx = init_ctx();
    server = open_connection(hostname, portnum);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);
    if (SSL_connect(ssl) == FAIL)
        ERR_print_errors_fp(stderr);
    else{
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        show_certs(ssl);
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
                bytes = SSL_read(ssl, buf, sizeof(buf));
                if (bytes > 0){
                    buf[bytes] = 0;
                    printf("\nMessage from client: %s\n", buf);
                }
            }
        }
        SSL_free(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}

int open_connection(char* hostname, int port){
    int con_so;
    struct hostent* host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL){
        fprintf(stderr, "cannot resolve hostname %s\n", hostname);
        abort();
    }
    con_so = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if (connect(con_so, (struct sockaddr*)&addr, sizeof(addr)) != 0){
        close(con_so);
        fprintf(stderr, "cannot connect to server %s\n", hostname);
        abort();
    }
    return con_so;
}