/* Syscall hooks */

#ifndef _HOOKS_H
#define _HOOKS_H

// Performs every syscall hook
int __init hooks_init(void);

// Disables every syscall hook
void hooks_exit(void);

#endif
