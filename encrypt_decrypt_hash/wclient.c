/*	A simple SSL client
	It connects to the server,  makes a request and waits for the response
*/
#include "common.h"
#include "client.h"
#include <openssl/aes.h>
#include <openssl/hmac.h>

static char *host = HOST;
static int port = PORT;
static int require_server_auth = 1;

static int verify_digest(int fd, unsigned char *expected) {
	int i, bytes_read;
	unsigned int result_len;
	unsigned char buf[1024], hmac_value[32];
	//unsigned char KEY[] = "key";
	unsigned char *result;

	HMAC_CTX hmac;
	HMAC_CTX_init(&hmac);
	HMAC_Init_ex(&hmac, KEY, strlen((char *)KEY), EVP_sha256(), NULL);
 
	while((bytes_read = read(fd, buf, 1024)) > 0) {
		HMAC_Update(&hmac, buf, bytes_read);
	}

	HMAC_Final(&hmac, hmac_value, &result_len);
	HMAC_CTX_cleanup(&hmac);

	result = (unsigned char*) malloc (2*result_len*sizeof(unsigned char)+1);
	for (i = 0; i < result_len; i++) {
		sprintf((char*)&(result[i*2]), "%02x",  hmac_value[i]);
	//	printf("%02x",  hmac_value[i]);
	}
	result[64] = '\0';
	
    if (strcmp((char*) result, (char*) expected) == 0) {
        printf("Test ok, result length %d\n", result_len);
		return 0;
	}

    return 1;
}

static int keys_request_decrypt(SSL *sslHandle)
{
	char *request = 0;
	char buf[BUFSIZE];
	int request_len;

	char *REQUEST_TEMPLATE = "Request for decryption keys\0";

	/* Now construct our request */
	request_len = strlen(REQUEST_TEMPLATE) + strlen(host) + 6;
	if(!(request = (char *)malloc(request_len)))
		err_exit("Couldn't allocate request");

	/* Write the request to a character array pointed by request */
	snprintf(request, request_len, REQUEST_TEMPLATE, host, port);

	/* Find the exact request_len */
	request_len = strlen(request);

	int returnVal;
	returnVal = SSL_write(sslHandle, request, request_len);
	switch(SSL_get_error(sslHandle, returnVal)){      
		case SSL_ERROR_NONE:
			if(request_len != returnVal)
				err_exit("Incomplete write!");
			break;
		default:
			berr_exit("SSL write problem");
	}

	returnVal = SSL_read(sslHandle, buf, BUFSIZE);
	switch(SSL_get_error(sslHandle, returnVal)) {
		case SSL_ERROR_NONE:
	//		response_len = returnVal;
			break;
		case SSL_ERROR_SYSCALL:
			fprintf(stderr, "SSL Error: Premature close\n");
			goto done;
		default:
			berr_exit("SSL read problem");
	}
	
//	fwrite(buf, 1, response_len, stdout);

	// ckey and ivec are the two 128-bits keys necesary
 	unsigned char ckey[17];
	unsigned char ivec[17];
	unsigned char digest[65];

//	printf("%s", buf);
	strncpy((char*)ckey, buf, 16);
	ckey[16] = '\0';
	strncpy((char*)ivec, (buf + 16), 16);
	ivec[16] = '\0';
	strncpy((char*)digest, (buf + 32), 64);
	digest[64] = '\0';

//	printf("%s", ckey);
//	printf("%s", ivec);
	printf("digest: %s\n", digest);
	SSL_shutdown(sslHandle);
	
	FILE *ifp = fopen("/home/ashdharan/encrypt_decrypt/encrypted_file", "r");
	FILE *ofp = fopen("/home/ashdharan/encrypt_decrypt/decrypted_file", "w");

	/* data structure that contains the key itself */
	AES_KEY key;

	/* set the decryption key */
	AES_set_encrypt_key(ckey, 128, &key);

	int num = AES_BLOCK_SIZE;
	int bytes_read = 0;
	unsigned char indata[AES_BLOCK_SIZE];
	unsigned char outdata[AES_BLOCK_SIZE];

	while (1) {
    	bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);

	    AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &num, AES_DECRYPT);

	    fwrite(outdata, 1, bytes_read, ofp);
	    if (bytes_read < AES_BLOCK_SIZE)
	    break;
	  }

	fclose(ifp);
	fclose(ofp);

	int fd;
	if((fd = open("/home/ashdharan/encrypt_decrypt/decrypted_file", O_RDONLY) ) == -1) {
		printf("Couldnt open input file, try again\n");
		return 1;
	}

	//verify_digest(fd, (unsigned char*)"c67215d433649e6e6ba2d82977a47f8238a99e6b48a18e3b6f3489ca258c991d");
	verify_digest(fd, digest);
	done:
		SSL_free(sslHandle);
		free(request);
		return(0);
	}
    
int main(int argc, char *argv[])
{
	SSL_CTX *ctx;
	SSL *sslHandle;
	BIO *sbio;
	int socket_fd;
	extern char *optarg;

	/* Build our SSL context*/
	ctx = initialize_ctx(KEYFILE);

	/* Connect the TCP socket*/
	socket_fd = tcp_connect(host, port);

	/* Connect the SSL socket */
	sslHandle = SSL_new(ctx);
	sbio = BIO_new_socket(socket_fd, BIO_NOCLOSE);
	SSL_set_bio(sslHandle, sbio, sbio);

	if(SSL_connect(sslHandle) <= 0)
		berr_exit("SSL connect error");
	if(require_server_auth)
		check_cert(sslHandle, host);
 
    /* Now make our Decryption keys request */
    keys_request_decrypt(sslHandle);

    /* Shutdown the socket */
    destroy_ctx(ctx);
    close(socket_fd);

    exit(0);
}
