/*	A simple SSL client
	It connects to the server,  makes a request and waits for the response
*/
#include "common.h"
#include "client.h"
#include <openssl/aes.h>
#include <openssl/hmac.h>

static const char *host = HOST;
static int port = PORT;
static int require_server_auth = 1;

uint8_t* keys_digest_request_decrypt(SSL*, const char*, uint8_t *);
SSL* wclient_start(void);
int wclient_end(void);

static long get_file_size(FILE *f)
{
	long where, size;

    /* XXX: on Unix systems, using fstat() probably makes more sense */

	where = ftell(f);
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, where, SEEK_SET);

	return size;
}

static uint8_t verify_digest(uint8_t *decrypted_kernel, unsigned char *expected, size_t decrypted_kernel_size) {
//static int verify_digest(int fd, unsigned char *expected) {
	int i = 0, bytes_read = 0;
	unsigned int result_len;
	unsigned char hmac_value[32];
	unsigned char *result;

	HMAC_CTX hmac;
	HMAC_CTX_init(&hmac);
	HMAC_Init_ex(&hmac, KEY, strlen((char *)KEY), EVP_sha256(), NULL);
 
	HMAC_Update(&hmac, decrypted_kernel, decrypted_kernel_size);
	HMAC_Final(&hmac, hmac_value, &result_len);
	HMAC_CTX_cleanup(&hmac);

	result = (unsigned char*) malloc (2*result_len*sizeof(unsigned char)+1);
	printf("\nresult_len: %d", result_len);
	for (i = 0; i < result_len; i++) {
		sprintf((char*)&(result[i*2]), "%02x",  hmac_value[i]);
	//	printf("%02x",  hmac_value[i]);
	}
	result[64] = '\0';

	printf("\nexpected  : %s", expected);
	printf("\ncalculated: %s", result);	
	 if (strcmp((char*) result, (char*) expected) == 0) {
        	printf("\nTest ok, result length %d\n", result_len);
		return 1;
	}
	else { fprintf(stdout, "\nHey you change the hash!!"); fflush(stdout);}

    return 0;
}

uint8_t* keys_digest_request_decrypt(SSL *sslHandle, const char* kernel_filename, uint8_t *decrypted_kernel) 
//static int keys_request_decrypt(SSL *sslHandle, const char *kernel_filename)
{
	char *request = 0;
	char buf[BUFSIZE];
	int request_len;

	const char *REQUEST_TEMPLATE = "Request for decryption keys\0";

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
	

	// ckey and ivec are the two 128-bits keys necesary
	unsigned char ckey[17];
	unsigned char ivec[17];
	unsigned char digest[65];
	
	strncpy((char*)ckey, buf, 16);
	ckey[16] = '\0';

	strncpy((char*)ivec, (buf + 16), 16);
	ivec[16] = '\0';
	
	strncpy((char*)digest, (buf + 32), 64);
	digest[64] = '\0';
	
	printf("ckey: %s\n", ckey);
	printf("ivec: %s\n", ivec);
	printf("digest: %s\n", digest);

	// Client initiated SSL teardown
	SSL_shutdown(sslHandle);

	FILE *ifp = fopen(kernel_filename, "r");
	FILE *ofp = fopen("/home/jitesh/repos/ashwin/tests/decrypted_file", "w");

	size_t kernel_size = get_file_size(ifp);
	printf("Kernel filename: %s\n", kernel_filename);
	printf("Kernel filesize: %d\n", kernel_size);

	decrypted_kernel = (uint8_t*) qemu_malloc(kernel_size + 16);

	/* data structure that contains the key itself */
	AES_KEY key;

	/* set the decryption key */
	AES_set_encrypt_key(ckey, 128, &key);

	int num = AES_BLOCK_SIZE;
	int bytes_read = 0;
	unsigned char indata[AES_BLOCK_SIZE];
	unsigned char outdata[AES_BLOCK_SIZE];

	int i = 0;
	while (1) {
		bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);

		if (bytes_read == 0)
			break;
		AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &num, AES_DECRYPT);
		fwrite(outdata, 1, bytes_read, ofp);

		memcpy((decrypted_kernel + i), indata, AES_BLOCK_SIZE);
		if(memcmp(decrypted_kernel + i, indata, 16)) { printf("Error Copying"); exit(1);} 
		if (bytes_read < AES_BLOCK_SIZE)
		    break;
		i += AES_BLOCK_SIZE;
	}

	decrypted_kernel[i] = '\0';
	printf("\nbytes_read: %d", i);
	printf("\ncompare value: %d", memcmp(decrypted_kernel + i, outdata, bytes_read));

	fclose(ifp);
	fclose(ofp);

	if (!verify_digest(decrypted_kernel, digest, kernel_size)) {
		printf("Couldn't verify the digest");
		return NULL;
	}

	done:
		SSL_free(sslHandle);
		free(request);
		return(decrypted_kernel);
}
    
static SSL_CTX *ctx;
static SSL *sslHandle;
int socket_fd;

SSL* wclient_start(void)
{
	BIO *sbio;

	/* Build our SSL context*/
	ctx = initialize_ctx(KEYFILE);

	/* Connect the TCP socket*/
	socket_fd = my_tcp_connect(host, port);

	/* Connect the SSL socket */
	sslHandle = SSL_new(ctx);
	sbio = BIO_new_socket(socket_fd, BIO_NOCLOSE);
	SSL_set_bio(sslHandle, sbio, sbio);

	if(SSL_connect(sslHandle) <= 0)
		berr_exit("SSL connect error");
	if(require_server_auth)
		check_cert(sslHandle, host);
 
	return sslHandle;

	/* Following functionality has been moved to qemu/hw/pc.c@load_linux() */
	    //keys_request_decrypt(sslHandle, kernel_filename);
	    //keys_request(sslHandle);
}

int wclient_end(void) {
    /* Shutdown the socket */
    destroy_ctx(ctx);
    close(socket_fd);

    return 0;
}

