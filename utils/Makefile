all:	encrypt decrypt

encrypt:	encrypt.c
	gcc -o encrypt encrypt.c -lcrypto

decrypt:	decrypt.c
	gcc -o decrypt decrypt.c -lcrypto

clean:
	rm -f encrypt decrypt 
