#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/utsname.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>

#define SOCK_PATH	"secure_socket"
#define	MAX_ARGS	128
#define LAUNCHER	"/usr/bin/qemu-system-x86_64"	

unsigned char original_launcher_sha1[] = {0x76, 0xf8, 0x7a, 0x94, 0xd2, 0xe8, 0xd2, 0xb4, 0xb6, 0x94, 0xf2, 0x73, 0x18, 0xab, 0x81, 0x8e, 0x0c, 0x8f, 0x9e, 0x99};

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

void split_args(char *command, char *args, char *qemu_argv[MAX_ARGS])
{
	int i;
	char *arg;

	qemu_argv[0] = basename(command);
	arg = strtok(args, " \n\t");
	for(i = 1; i < MAX_ARGS - 1; i++) {
		if (arg == NULL)
			break;
		qemu_argv[i] = arg;
		arg = strtok(NULL, " \n\t");
	}
	qemu_argv[i] = NULL;
}

int main(void)
{
	int sock, s2, t, len, rc;
	struct sockaddr_un local, remote;
	char str[1024];
	unsigned char sha1[20];
	char *args, *secret;
	char *qemu_argv[MAX_ARGS];
	extern char **environ;
	pid_t pid;

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "Error: Socket create failed\n");
		exit(1);
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, SOCK_PATH);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(sock, (struct sockaddr *)&local, len) == -1) {
		fprintf(stderr, "Error: bind failed\n");
		exit(1);
	}

	if (listen(sock, 5) == -1) {
		fprintf(stderr, "Error: listen failed\n");
		exit(1);
	}

	for (;;) {
		int done, n;
		t = sizeof(remote);
		if ((s2 = accept(sock, (struct sockaddr *)&remote, &t)) == -1) {
			fprintf(stderr, "Error: accept failed\n");
			exit(1);
		}

		n = recv(s2, str, 1023, 0);
		if (n < 0)
			fprintf(stderr, "Error: recv failed\n");
		str[n] = '\0';
		printf("Received: %s", str);

		close(s2);

		/* Hash of the launcher */
		rc = get_hash(LAUNCHER, sha1);
		if (rc != 0)
			return rc;

		if (memcmp(sha1, original_launcher_sha1, 20) != 0) {
			fprintf(stderr, "Error: Hash mismatch\n");
			//continue;
		}
		
		args = strtok(str, ";");
		secret = strtok(NULL, "; \n\t");

		split_args(LAUNCHER, args, qemu_argv);
		pid = fork();
		if (pid == 0) { /* child */	
			setenv("SRK_SECRET", secret, 1);
			execv(LAUNCHER, qemu_argv);
			/* Won't reach here */
		} else {
			rc = get_hash(LAUNCHER, sha1);
			if (rc == 0) {
				if (memcmp(sha1, original_launcher_sha1, 20) == 0) 
					continue;
			}
			/* If reached here, then launcher binary has been maliciously
			 * modified. Kill the child */
			kill(pid, SIGKILL);
			continue;
		}

	}

	close(sock);
	return 0;
}
