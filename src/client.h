#ifndef CLIENT_H
#define CLIENT_H

#include <errno.h> /*USING THE ERROR LIBRARY FOR FINDING ERRORS*/
#include <stdio.h> /*standard i/o*/
#include <unistd.h> /*FOR USING FORK for at a time send and receive messages*/ 
#include <malloc.h> /*FOR MEMORY ALLOCATION */
#include <string.h> /*using fgets funtions for geting input from user*/
#include <sys/socket.h> /*for creating sockets*/
#include <resolv.h> /*server to find out the runner's IP address*/ 
#include <netdb.h> /*definitions for network database operations */
#include <openssl/ssl.h> /*using openssl function's and certificates and configuring them*/
#include <openssl/err.h> /* helps in finding out openssl errors*/
#include <unistd.h>  /*FOR USING FORK for at a time send and receive messages*/ 

#define FAIL    -1 /*for error output == -1 */
#define BUFFER  1024  /*buffer for reading messages*/

int client(char* hostname, int portnum);
int open_connection(char* hostname, int port);

#endif /* CLIENT_H */