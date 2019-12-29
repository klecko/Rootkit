#ifndef _CONFIG_H
#define _CONFIG_H

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Klecko");
MODULE_DESCRIPTION("Rootkit by Klecko");
MODULE_VERSION("0.1");

#define HIDE_MODULE     0
#define PROC_FILENAME   "rootkit_proc"
#define HOOK_GETDENTS   1
#define HOOK_GETDENTS64 1
#define HOOK_STAT       1
#define HOOK_LSTAT      1
#define BACKDOOR        0

#define HIDE_STR "HiddenKlecko"

#endif
