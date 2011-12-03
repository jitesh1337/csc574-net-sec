 /* A simple SSL server */
#include "common.h"
#include "server.h"
#include <openssl/aes.h>

static int response_server(SSL *sslHandle,  int socket_fd) {
	char buf[BUFSIZE];
	int returnVal;
	BIO *io, *ssl_bio;

	io = BIO_new(BIO_f_buffer());
	ssl_bio = BIO_new(BIO_f_ssl());
	BIO_set_ssl(ssl_bio, sslHandle, BIO_CLOSE);
	BIO_push(io, ssl_bio);
	
	FILE *ifp = fopen("in_params", "r");
	if (ifp == NULL) {
		fprintf(stderr, "Can't open in_params file to read configuration\n");
		exit(1);
	}

	/* Read key + ivec + kernel's HMAC */
	fread(buf, 1, 2*AES_BLOCK_SIZE+64, ifp);

	/* Write to SSL socket stream */
	if((returnVal = BIO_write(io, buf, 2*AES_BLOCK_SIZE+64)) <= 0)
		err_exit("Write error");

	if((returnVal = BIO_flush(io)) < 0)
		err_exit("Error flushing BIO");

    returnVal = SSL_shutdown(sslHandle);
    if(!returnVal){
      /* If we called SSL_shutdown() first then
         we always get return value of '0'. In
         this case,  try again,  but first send a
         TCP FIN to trigger the other side's
         close_notify*/
      shutdown(socket_fd, 1);
      returnVal = SSL_shutdown(sslHandle);
    }
      
	switch(returnVal) {  
		case 1:
			break; /* Success */
		case 0:
		case -1:
		default:
			berr_exit("Shutdown failed");
	}

    SSL_free(sslHandle);
    close(socket_fd);

    return(0);
  }
 
int main(int argc, char **argv) {
	int sockserver, socket_fd;
	BIO *sbio;
	SSL_CTX *ctx;
	SSL *sslHandle;
	int returnVal;
    char buf[BUFSIZE];

	/* Build our SSL context*/
	ctx = initialize_ctx(KEYFILE);

	sockserver = tcp_listen();

	if((socket_fd = accept(sockserver, 0, 0)) < 0)
		err_exit("Problem accepting");

	sbio = BIO_new_socket(socket_fd, BIO_NOCLOSE);
	sslHandle = SSL_new(ctx);
	SSL_set_bio(sslHandle, sbio, sbio);

	if((returnVal = SSL_accept(sslHandle) <= 0))
		berr_exit("SSL accept error");

	returnVal = SSL_read(sslHandle, buf, BUFSIZE);
	response_server(sslHandle, socket_fd);
	exit(0);

	destroy_ctx(ctx);
	exit(0);
}
