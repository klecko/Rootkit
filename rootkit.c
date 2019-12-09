#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>

#include "sys.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Klecko");
MODULE_DESCRIPTION("Rootkit by Klecko");
MODULE_VERSION("0.1");


//insmod
static int lkm_init(void){
    printk(KERN_INFO "Starting Rootkit -----------------\n");
    printk(KERN_INFO "%p\n", sys_call_table);
    return 0;
}

//rmmod
static void lkm_exit(void){
    printk(KERN_INFO "Finishing Rootkit ----------------\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

