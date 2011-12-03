#include "common.h"
#include "client.h"
#include <openssl/err.h>

BIO *bio_err = 0;

/* A simple error and exit routine*/
int err_exit(char *string) {
	fprintf(stderr, "%s\n", string);
	exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char *string) {
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}

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

/* unsigned char * get_key(char *der_file, int *size)
{

    X509 *crt = NULL;
	FILE *ifp = fopen(der_file, "r");
	int bytes_read = 0;
	char indata[1024];

	int keylength = get_file_size(ifp);
	unsigned char *key = (unsigned char*) malloc(sizeof(unsigned char) * keylength);

	bytes_read = fread(key, 1, keylength, ifp);
	fclose(ifp);
	*size = bytes_read;
	//printf("bytes_read: %d\n", bytes_read);

    return key;
} */

unsigned char *get_key(char *der_file, int *key_size)
{
	char *srk_passwd = NULL, *data, *srk_passwd_tmp;
	int i;
	
	srk_passwd = getenv("SRK_SECRET");
	if (srk_passwd == NULL) {
		fprintf(stderr, "Unable to get SRK secret. Exiting..\n");
		exit(1);
	}

	srk_passwd_tmp = malloc(100);
	strcpy(srk_passwd_tmp, srk_passwd);

	tpmUnsealFile(der_file, &data, key_size, FALSE, srk_passwd_tmp);
	return data;
}


SSL_CTX* initialize_ctx(char *keyfile) {//, char *password) {
	SSL_METHOD *ssl_method;
	SSL_CTX *ctx;
	unsigned char *der_key;
	int size;

	if(!bio_err) {
	  /* Global system initialization*/
	  SSL_library_init();
	  SSL_load_error_strings();
	  
	  /* An error write context */
	  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	/* Create our context*/
	ssl_method = SSLv23_method();
	ctx = SSL_CTX_new(ssl_method);

	/* Load our keys and certificates*/
	if(SSL_CTX_use_certificate_chain_file(ctx, keyfile) != 1)
		berr_exit("Can't read certificate file");

	der_key = get_key(PRIVATE_KEYFILE, &size);
	//pass = password;
//	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	//if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)))
	if(SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, der_key, size) != 1) {
		berr_exit("Can't read key file");
	}

	/* Load the CAs we trust*/
	if(SSL_CTX_load_verify_locations(ctx, CA_LIST, 0) != 1)
		berr_exit("Can't read CA list");
	
	#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
		SSL_CTX_set_verify_depth(ctx, 1);
	#endif

	return ctx;
}
     
void destroy_ctx(SSL_CTX *ctx) {
	SSL_CTX_free(ctx);
}
