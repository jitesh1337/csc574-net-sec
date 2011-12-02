#ifndef _client_h
#define _client_h

#define KEYFILE "/etc/pki/tls/certs/client.pem"
#define PRIVATE_KEYFILE "/etc/pki/tls/certs/client.der.private"

int tcp_connect(char *host, int port);
void check_cert(SSL *ssl, char *host);

#endif

