#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "process.h"
#include "limits.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "devices/input.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&file_system_lock);
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // We are getting the number of the system call from the interrupt frame
  int callNumber = -1;
  void *arg = f->esp;
  bool validAddress = is_valid_address(arg);

  // We are checking if the address is valid
  if (validAddress)
  {
    callNumber = getValueAtAddress(arg);
  }

  arg += 4;

  // If the address is valid, we make call to the required method
  switch (callNumber)
  {
  case SYS_HALT:
  {
    halt();
    break;
  }
  case SYS_EXIT:
  {
    bool validAddress = is_valid_address(arg);
    if (validAddress)
    {
    exit(getValueAtAddress(arg));
    }
    else{
      exit(-1);
    }
    break;
  }
  case SYS_EXEC:
  {
    bool validAddress = is_valid_address(arg);
    if (validAddress)
    {
      int *file_name = (int *) f->esp + 1;
      f->eax = exec((const char *)file_name[0]);
    }
    else
    {
      exit(-1);
    }
    break;
  }
  case SYS_WAIT:
  {
    f->eax = wait(getValueAtAddress(arg));
    break;
  }

  case SYS_CREATE:
  {
    bool validAddress = is_valid_address(arg);
    int *file_name = (int *) f->esp + 1;
    int *size = (int *) f->esp + 2;
    if (validAddress)
    {
      f->eax = create((const char *)file_name[0], (unsigned)size[0]);
    }
    else
    {
      exit(-1);
    }
    break;
  }
  case SYS_REMOVE:
  {
    int validAddress = is_valid_address(arg);
    if (validAddress)
    {
      int *file_name = (int *) f->esp + 1;
      f->eax = remove((const char *)file_name[0]);
    }
    else
    {
      exit(-1);
    }
    break;
  }

  case SYS_OPEN:
  {
    int validAddress = is_valid_address(arg);
    if (validAddress)
    {
      int *open_file_name = (int *) f->esp + 1;
      f->eax = open((const char *)open_file_name[0]);
    }
    else
    {
      exit(-1);
    }
    break;
  }

  case SYS_FILESIZE:
  {
    f->eax = filesize(getValueAtAddress(arg));
    break;
  }

  case SYS_READ:
  {
    int arg1 = getValueAtAddress(arg);
    arg += 4;
    int arg2 = getValueAtAddress(arg);
    arg += 4;
    int arg3 = getValueAtAddress(arg);
   //int read (int fd, void *buffer, unsigned size)
    bool valid1 = is_valid_address((const void *)arg2);
    void *endAddress = ((void *)arg2) + arg3;
    bool valid2 = is_valid_address((const void *)endAddress);
    if (valid1 && valid2)
    {
      f->eax = read(arg1, (void *)arg2, (unsigned)arg3);
    }
    break;
  }
  case SYS_WRITE:
  {
    int arg1 = getValueAtAddress(arg);
    arg += 4;
    int arg2 = getValueAtAddress(arg);
    arg += 4;
    int arg3 = getValueAtAddress(arg);

    bool valid1 = is_valid_address((const void *)arg2);
    void *endAddress = ((void *)arg2) + arg3;
    bool valid2 = is_valid_address((const void *)endAddress);
    if (valid1 && valid2)
    {
      f->eax = write(arg1, (void *)arg2, (unsigned)arg3);
    }
    break;
  }
  case SYS_SEEK:
  {
    bool ValidAddress = is_valid_address(arg);
    int arg1 = getValueAtAddress(arg);
    arg += 4;
    int arg2 = getValueAtAddress(arg);
    if (ValidAddress)
    {
      seek(arg1, (unsigned)arg2);
    }
    else
    {
      exit(-1);
    }
    break;
  }
  case SYS_TELL:
  {
    f->eax = tell(getValueAtAddress(arg));
    break;
  }

  case SYS_CLOSE:
  {
    close(getValueAtAddress(arg));
    break;
  }
  default:
  {
    exit(-1);
    break;
  }
  }
}

// System Call functions for switch case
void halt()
{
  shutdown_power_off();
}

void exit(int status)
{
    struct thread *cur = thread_current();
    printf ("%s: exit(%d)\n", cur -> name, status);
    cur->exit_status = status;
    thread_exit();

}

tid_t exec(const char *command_line)
{
    struct thread* parent = thread_current();
    tid_t pid = -1;
    lock_acquire(&file_system_lock);
    pid = process_execute(command_line);
    lock_release(&file_system_lock);
    return pid;
}

int wait(tid_t pid)
{
  return process_wait(pid);
}

bool create(const char *file, unsigned size)
{
  bool return_val;
  lock_acquire(&file_system_lock);
  return_val = filesys_create(file, size);
  lock_release(&file_system_lock);
  return return_val;
}

bool remove(const char *file)
{
  bool return_val;
  lock_acquire(&file_system_lock);
  return_val = filesys_remove(file);
  lock_release(&file_system_lock);
  return return_val;
}

int open(const char *file)
{
  if (file == NULL)
  {
    return -1;
  }
  lock_acquire(&file_system_lock);
  struct file *openedFile = filesys_open(file);
  lock_release(&file_system_lock);

  if (openedFile == NULL)
  {
    return -1;
  }

  struct thread *currentThread = thread_current();
  currentThread->file_descriptor_size = currentThread->file_descriptor_size + 1;
  int newFd = currentThread->file_descriptor_size;
  struct fd_entry *fdentry = (struct fd_entry *)malloc(sizeof(struct fd_entry));
  if (fdentry == NULL)
  {
    return -1;
  }

  fdentry->fd_id = newFd;
  fdentry->entry_file = openedFile;
  list_push_back(&currentThread->file_descriptor_list, &fdentry->elem);

  return newFd;
}

int filesize(int fd)
{
  int return_val;
  struct file *givenFile = get_file_descriptor(fd)->entry_file;
  lock_acquire(&file_system_lock);
  return_val = file_length(givenFile);
  lock_release(&file_system_lock);
  return return_val;
}

int read(int fd, void *buffer, unsigned size)
{
  if (buffer == NULL)
  {
    return -1;
  }

  if (fd > 0)
  {
    struct fd_entry *fdEntry = get_file_descriptor(fd);
    if (fdEntry == NULL)
    {
      return -1;
    }
    struct file *entryFile = fdEntry->entry_file;

    lock_acquire(&file_system_lock);
    int bytesRead = file_read(entryFile, buffer, size);
    lock_release(&file_system_lock);

    if (bytesRead < (int)size && bytesRead != 0)
    {
      return -1;
    }

    return bytesRead;
  }
  else if (fd == 0)
  {
    return input_getc();
  }

  return -1;
}

int write(int fd, const void *buffer, unsigned size)
{
  if (buffer == NULL)
  {
    return -1;
  }

  if (fd > 1)
  {
    struct fd_entry *fdEntry = get_file_descriptor(fd);
    if (fdEntry == NULL)
    {
      return -1;
    }

    struct file *entryFile = fdEntry->entry_file;

    lock_acquire(&file_system_lock);
    int bytesWritten = file_write(entryFile, buffer, size);
    lock_release(&file_system_lock);

    return bytesWritten;
  }
  else if (fd == 1)
  {
    putbuf((const char *)buffer, size);
    return (int)size;
  }

  return -1;
}

void seek(int fd, unsigned position)
{
  struct fd_entry *fd_ent = get_file_descriptor(fd);
  if (fd_ent != NULL)
  {
    struct file *entryFile = fd_ent->entry_file;

    lock_acquire(&file_system_lock);
    file_seek(entryFile, position);
    lock_release(&file_system_lock);
  }
  else
  {
    return;
  }
}

unsigned tell(int fd)
{
  struct fd_entry *fd_ent = get_file_descriptor(fd);
  if (fd_ent != NULL)
  {
    struct file *entryFile = fd_ent->entry_file;

    lock_acquire(&file_system_lock);
    unsigned position = file_tell(entryFile);
    lock_release(&file_system_lock);
    return position;
  }
  else
  {
    return UINT_MAX;
  }
}

void close(int fd)
{
  struct fd_entry *fd_ent = get_file_descriptor(fd);
  struct file *entryFile = fd_ent->entry_file;

  if (fd_ent != NULL)
  {
    lock_acquire(&file_system_lock);
    file_close(entryFile);
    lock_release(&file_system_lock);
  }
  else
  {
    return;
  }
}

// Close all may need to be defined as well

int getValueAtAddress(const void *address)
{
  return *((int *)address);
}

bool is_valid_address(const void *address)
{
  bool isPointer = true;
  uint32_t *page_directory = thread_current()->pagedir;

  for (int i = 0; i < 5; i++)
  {
    if (!is_user_vaddr(address + i) || pagedir_get_page(page_directory, address + i) == NULL)
    {
      return false;
    }
  }

  void *pointer = pagedir_get_page(page_directory, address);
  if (pointer == NULL)
  {
    return false;
  }

  return isPointer;
}

struct fd_entry *get_file_descriptor(int fd)
{
  struct thread *current_thread = thread_current();
  struct list *fd_list = &current_thread->file_descriptor_list;

  for (struct list_elem *elem = list_begin(fd_list); elem != list_end(fd_list); elem = list_next(elem))
  {
    struct fd_entry *fdElement = list_entry(elem, struct fd_entry, elem);
    if (fdElement->fd_id == fd)
    {
      return fdElement;
    }
  }
  return NULL;
}