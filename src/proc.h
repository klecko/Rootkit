#ifndef _PROC_H
#define _PROC_H

// Creates and hides the virtual proc file
int __init proc_init(void);

// Unhides and removes the virtual proc file
void proc_exit(void);

#endif
