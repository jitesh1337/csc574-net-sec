#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>

int main(int argc, char *argv[])
{
  int bytes_read, bytes_written;
  unsigned char indata[AES_BLOCK_SIZE];
  unsigned char outdata[AES_BLOCK_SIZE];

  /* ckey and ivec are the two 128-bits keys necesary to
     en- and recrypt your data.  Note that ckey can be
     192 or 256 bits as well */
  unsigned char ckey[] =  "thiskeyisverybad";
  unsigned char ivec[] = "dontusethisinput";

  if (argc <= 2) {
	  printf("%s will atleast take two args: encrypted file and target decrypted file\n", argv[0]);
	  exit(1);
  }

  FILE *ifp = fopen(argv[1], "r");
  if (ifp == NULL) {
	  fprintf(stderr, "Error: opening file %s to read\n", argv[1]);
	  exit(1);
  }

  FILE *ofp = fopen(argv[2], "w");
  if (ofp == NULL) {
	  fprintf(stderr, "Error: opening %s to write\n", argv[2]);
	  exit(1);
  }

  /* data structure that contains the key itself */
  AES_KEY key;

  /* set the decryption key */
  AES_set_encrypt_key(ckey, 128, &key);

  int num = 16;

  while (1) {
    bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);

    AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &num,
                   AES_DECRYPT);

    bytes_written = fwrite(outdata, 1, bytes_read, ofp);
    if (bytes_read < AES_BLOCK_SIZE)
  	break;
  }
 
  fclose(ifp);
  fclose(ofp);
}
