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
    ctx = init_client_ctx();
    server = open_connection(hostname, portnum);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);
    int status = -1;
    status = SSL_connect(ssl);
    if (status <= 0){
        int ret = 0;
        SSL_get_error(ssl, ret);
        ERR_print_errors_fp(stderr);
    }
    else{
        X509* temp = SSL_get0_peer_certificate(ssl);
        X509_NAME* name = X509_get_subject_name(temp);
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
    int ret = 1;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    char* old_ip = inet_ntoa(addr.sin_addr);
    if (ret = connect(con_so, (struct sockaddr*)&addr, sizeof(addr)) != 0){
        char* er = strerror(errno);
        close(con_so);
        fprintf(stderr, "cannot connect to server %s\n", hostname);
        abort();
    }
    struct sockaddr_in peeraddr;
    socklen_t addrlen = sizeof(peeraddr);
    getpeername(con_so, (struct sockaddr*)&peeraddr, &addrlen);
    char* ip = inet_ntoa(peeraddr.sin_addr);
    return con_so;
}