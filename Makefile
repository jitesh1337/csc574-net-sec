all:	secure_launcher.c
	gcc secure_launcher.c -o secure_launcher -ltspi -Wall -lcrypto

clean:
	rm -f secure_launcher
