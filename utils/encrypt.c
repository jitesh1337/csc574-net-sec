#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/aes.h>

int main(int argc, char *argv[])
{
  int bytes_read, bytes_written;
  unsigned char indata[AES_BLOCK_SIZE];
  unsigned char outdata[AES_BLOCK_SIZE];
  char infile[1024], *outfile, *tmp;

  /* ckey and ivec are the two 128-bits keys necesary to
     en- and recrypt your data.  Note that ckey can be
     192 or 256 bits as well */
  unsigned char ckey[] =  "thiskeyisverybad";
  unsigned char ivec[] = "dontusethisinput";

  if (argc <= 1) {
	  printf("%s will atleast take one argument: the file to be encrypted\n", argv[0]);
	  exit(1);
  }

  snprintf(infile, 1023, "%s", argv[1]);
  FILE *ifp = fopen(infile, "r");
  if (ifp == NULL) {
	  fprintf(stderr, "Error: opening file %s to read\n", infile);
	  exit(1);
  }

  tmp = basename(infile);
  outfile = malloc(strlen(tmp) + 5);
  snprintf(outfile, 1023, "%s.enc", tmp);
  FILE *ofp = fopen(outfile, "w");
  if (ofp == NULL) {
	  fprintf(stderr, "Error: opening %s to write\n", outfile);
	  exit(1);
  }
  /* data structure that contains the key itself */
  AES_KEY key;

  /* set the encryption key */
  AES_set_encrypt_key(ckey, 128, &key);

  int num = 16;

  while (1) {
    bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);

    AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &num,
                   AES_ENCRYPT);

    bytes_written = fwrite(outdata, 1, bytes_read, ofp);
    if (bytes_read < AES_BLOCK_SIZE)
  	break;
  }
 
  fclose(ifp);
  fclose(ofp);
}
