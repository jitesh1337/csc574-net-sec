#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "secure_socket"

int main(void)
{
	int sock, s2, t, len;
	struct sockaddr_un local, remote;
	char str[1024];

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

		n = recv(s2, str, 1024, 0);
		if (n < 0)
			fprintf(stderr, "Error: recv failed\n");
		str[n] = '\0';

		printf("Received: %s", str);

		close(s2);
	}

	close(sock);
	return 0;
}
