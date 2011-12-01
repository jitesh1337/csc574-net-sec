#ifndef _client_h
#define _client_h

#define KEYFILE "client.pem"

int tcp_connect(char *host, int port);
void check_cert(SSL *ssl, char *host);

#endif

