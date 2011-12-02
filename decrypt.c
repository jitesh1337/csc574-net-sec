#include <stdio.h>
#include <openssl/aes.h>

int main(void)
{
  int bytes_read, bytes_written;
  unsigned char indata[AES_BLOCK_SIZE];
  unsigned char outdata[AES_BLOCK_SIZE];

  /* ckey and ivec are the two 128-bits keys necesary to
     en- and recrypt your data.  Note that ckey can be
     192 or 256 bits as well */
  unsigned char ckey[] =  "thiskeyisverybad";
  unsigned char ivec[] = "dontusethisinput";

  FILE *ifp = fopen("/home/jitesh/repos/ashwin/tests/encrypted_kernel", "r");
  FILE *ofp = fopen("/home/jitesh/repos/ashwin/tests/decrypted_kernel", "w");
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
