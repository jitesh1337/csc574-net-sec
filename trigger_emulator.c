#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "secure_socket"

int main(void)
{
	int sock, t, len;
	struct sockaddr_un remote;
	char str[1024];

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "Error: Cannot create socket\n");
		exit(1);
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, SOCK_PATH);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(sock, (struct sockaddr *)&remote, len) == -1) {
		fprintf(stderr, "Error: Connect failed\n");
		exit(1);
	}

	fgets(str, 1024, stdin);
	if (send(sock, str, strlen(str), 0) == -1) {
		fprintf(stderr, "Error: Send failed\n");
		exit(1);
	}

	close(sock);

	return 0;
}
