#ifndef _HIDING_H
#define _HIDING_H

int is_module_hidden(void);
int is_file_hidden(const char* name);
int is_pid_hidden(int pid);
int pathname_includes_pid(const char* pathname);

int hide_module(void);
int unhide_module(void);
int hide_file(const char* name);
int unhide_file(const char* name);
int hide_pid(int pid);
int unhide_pid(int pid);
void delete_lists(void);

void print_hidden(void);
#endif