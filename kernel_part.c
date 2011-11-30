#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <trousers/tss.h>
#include <openssl/sha.h>

/* Get filename, return its hash. Use openssl's SHA1
 */
int get_hash(char *filename, unsigned char *sha1)
{
	int rc, fd;
	struct stat stat_buf;
	unsigned char *buf;

	rc = stat(filename, &stat_buf);
	if (rc != 0) {
		printf("Can't stat %s\n", filename);
		return -1;
	}

	buf = malloc(stat_buf.st_size);
	fd = open(filename, O_RDONLY);
	read(fd, buf, stat_buf.st_size);
	close(fd);
	
	SHA1(buf, stat_buf.st_size, sha1);
	free(buf);
	return 0;
}

/* Find currently running kernel and obtain its hash
 */
int get_kernel(unsigned char *sha1)
{
	struct utsname uname_info;
	char kernel_filename[1024];
	int rc;

	uname(&uname_info);
	snprintf(kernel_filename, 1023, "/boot/vmlinuz-%s", uname_info.release);
	rc = get_hash(kernel_filename, sha1);

	return rc;
}


int main(int argc, char *argv[])
{
	int rc;
	TSS_HCONTEXT    hContext;
	TSS_HTPM	hTPM;
	int i;
	unsigned int pcr_len = 0;
	unsigned char *pcr_value;
	unsigned char sha1[20];

	/* The argument being the executable */
	if (argc <= 1) {
		printf("Must give atleast one argument\n");
		exit(1);
	}

	/* Find out the currently running kernel and return its hash */
	rc = get_kernel(sha1);
	if (rc != 0) {
		printf("Kernel read failed\n");
		exit(1);
	}

	/* Start creating the TSS context */
	rc = Tspi_Context_Create(&hContext);
	if (rc != TSS_SUCCESS)
		printf("Context creation failed!\n");

	rc = Tspi_Context_Connect(hContext, NULL);
	if (rc != TSS_SUCCESS)
		printf("Context connection failed!\n");

	rc = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (rc != TSS_SUCCESS)
		printf("Getting TPM Object failed\n");

	rc = Tspi_TPM_PcrRead(hTPM, 16, &pcr_len, &pcr_value);
	printf("Length of data read: %d\n", pcr_len);
	for (i = 0; i < pcr_len; i++)
		printf("%x ", pcr_value[i]);
	printf("\n");

	/* Trousers wonkiness - have to pass SHA1 hash */
	rc = Tspi_TPM_PcrExtend(hTPM, 16, 20, sha1, NULL, 
			&pcr_len, &pcr_value);
	if (rc != TSS_SUCCESS) {
		printf("Kernel Extend failed : %d\n", rc);
	}


	printf("Length of extended PCR value: %d\n", pcr_len);
	for (i = 0; i < pcr_len; i++)
		printf("%x ", pcr_value[i]);
	printf("\n");

	free(pcr_value);
	Tspi_Context_Close(hContext);

	return 0;
}
