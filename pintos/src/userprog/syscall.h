#include <list.h>
#include "threads/thread.h"
#include "threads/synch.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct lock file_system_lock;

struct fd_entry{
    int fd_id;
    struct file *entry_file;
    struct list_elem elem;
};

void halt (void);
void exit (int status);
tid_t exec (const char *command_line);
int wait (tid_t pid);
bool create (const char *file, unsigned size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

struct fd_entry *get_file_descriptor(int fd);
bool is_valid_address(const void *address);
int getValueAtAddress(const void *address);

#endif /* userprog/syscall.h */
