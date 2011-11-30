all:	kernel_part secure_daemon trigger_emulator

kernel_part:	kernel_part.c
	gcc $< -o $@ -ltspi -Wall -lcrypto

secure_daemon:	secure_daemon.c
	gcc $< -o $@
	
trigger_emulator:	trigger_emulator.c
	gcc $< -o $@

clean:
	rm -f kernel_part secure_launcher trigger_emulator 
