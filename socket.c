/* $Id: socket.c 1.1 1995/01/01 07:11:14 cthuang Exp $
 *
 * This module has been modified by Radim Kolar for OS/2 emx
 */

/***********************************************************************
  module:       socket.c
  program:      popclient
  SCCS ID:      @(#)socket.c    1.5  4/1/94
  programmer:   Virginia Tech Computing Center
  compiler:     DEC RISC C compiler (Ultrix 4.1)
  environment:  DEC Ultrix 4.3 
  description:  UNIX sockets code.
 ***********************************************************************/
 
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>


SSL_CTX *ssl_ctx;
SSL *ssl;


SSL_CTX *initialize_ssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Error initializing SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ssl_ctx;
}

void cleanup_ssl(SSL_CTX *ctx) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();
}

int Socket(const char *host, int clientPort)
{
    int sock;
    unsigned long inaddr;
    struct sockaddr_in ad;
    struct hostent *hp;
    
    memset(&ad, 0, sizeof(ad));
    ad.sin_family = AF_INET;//设置为ipv4

    inaddr = inet_addr(host);//将host转换为ipv4
    if (inaddr != INADDR_NONE)
        memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
    else
    {
        hp = gethostbyname(host);
        if (hp == NULL)
            return -1;
        memcpy(&ad.sin_addr, hp->h_addr, hp->h_length);
    }
    ad.sin_port = htons(clientPort);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return sock;
    if (connect(sock, (struct sockaddr *)&ad, sizeof(ad)) < 0)
        return -1;

    if (clientPort == 443) {  //HTTPS connection
        SSL_CTX *ssl_ctx = initialize_ssl();
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            fprintf(stderr, "SSL handshake failed\n");
            SSL_free(ssl);
            close(sock);
            return -1;
        }
        return (int)(long)ssl;
    }
    return sock;
}


