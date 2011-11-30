#include <stdio.h>
#include <trousers/tss.h>

int main(int argc, char *argv[])
{
	char *srk_passwd, *data;
	int i, size;

	if (argc < 2) {
		printf("Atleast one arg needed!\n");
		exit(1);
	}

	srk_passwd = malloc(100);
	strcpy(srk_passwd, "12345");

	tpmUnsealFile(argv[1], &data, &size, FALSE, srk_passwd);
}
