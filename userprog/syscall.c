#include "userprog/syscall.h"
#include "userprog/process.h"
#include "devices/input.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/frame.h"



static void syscall_handler (struct intr_frame *);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */

static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

struct lock lock_filesys;

void
syscall_init (void)
{
  lock_init(&lock_filesys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void exit_proc(int exit_status) {
  if (lock_held_by_current_thread(&lock_filesys))
    lock_release(&lock_filesys);
  printf("%s: exit(%d)\n", thread_current()->name, exit_status);
  thread_current()->pcb->exit_status = exit_status;
  file_close(thread_current()->exec_file);
  thread_exit();
}

static void close_fd (int fd, struct list *fd_list) {
  lock_acquire(&lock_filesys);
  struct list_elem *e;
  struct fd* f_desc = NULL;
  for (e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e)) {
    f_desc = list_entry(e, struct fd, elem);
    if(f_desc->fd_num == fd) {
      break;
    }
  }
  if (f_desc == NULL){
    lock_release(&lock_filesys);
    return;
  }

  file_close(f_desc->file);
  list_remove(e);
  palloc_free_page(f_desc);

  lock_release(&lock_filesys);
}

static void invalid_access(void) {
  if (lock_held_by_current_thread(&lock_filesys))
    lock_release(&lock_filesys);
  exit_proc(-1);
}

static void read_mem(const uint8_t *uaddr, void* dst, int num_bytes) {
  for (int i = 0; i < num_bytes; i++) {
    if(is_user_vaddr(uaddr+i)) {
      int value = get_user(uaddr+i);
      if (value == -1) 
        invalid_access();
      else
        *(int*) (dst + i) = value;
    }
    else {
      invalid_access();
    }
  }
}

static struct fd* get_file_desc(struct list* fd_list, int fd_num) {
  struct list_elem *e;
  for (e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e)) {
    struct fd* desc = list_entry(e, struct fd, elem);
    if(desc->fd_num == fd_num) {
      return desc;
    }
  }
  return NULL;
}

static int read_file(int fd, void* buff, unsigned size) {
  int bytes_read = -1;
  lock_acquire(&lock_filesys);
  if (fd == 0) {
    for(unsigned i = 0; i < size; i++) {
      if(!put_user(buff+i, input_getc()))
        invalid_access();
    }
    bytes_read = size;
  }
  else {
    struct fd* f_desc = get_file_desc(&thread_current()->fd_list, fd);
    if(f_desc == NULL) 
      bytes_read = -1;
    else
      bytes_read = file_read (f_desc->file, buff, size);

  }
  lock_release(&lock_filesys);
  return bytes_read;
}

static int write_file (int fd, const void* buff, unsigned size) {
  lock_acquire(&lock_filesys);
  int bytes_written = -1;
  if (fd == 1) {
    putbuf(buff, size);
    bytes_written = size;
  }
  else {
    struct fd* f_desc = get_file_desc(&thread_current()->fd_list, fd);
    if(f_desc == NULL) 
      bytes_written = -1;
    else
      bytes_written = file_write (f_desc->file, buff, size);
  }
  lock_release(&lock_filesys);
  return bytes_written;
}

static void
syscall_handler (struct intr_frame *f)
{
#ifdef VM
  thread_current()->esp = f->esp;
#endif
  int syscall_num; 
  read_mem(f->esp, &syscall_num, sizeof(syscall_num));

  //printf ("Syscall_num: %d\n", syscall_num);
  switch (syscall_num) {
    case SYS_HALT: // 0
      {
        shutdown_power_off();
      }
      break;
    case SYS_EXIT: // 1
      {
        int exit_status;
        read_mem(f->esp+4, &exit_status, sizeof(exit_status));
        exit_proc(exit_status);
      }
      break;
    case SYS_EXEC: // 2
      {
        char* cmdline = NULL;
        read_mem(f->esp+4, &cmdline, sizeof(cmdline));
        if((cmdline == NULL) || get_user((const uint8_t*)cmdline) == -1){
		      exit_proc(-1);
	      }
        f->eax = process_execute(cmdline);
      }
      break;
    case SYS_WAIT: // 3
      {
        tid_t tid;
        read_mem(f->esp+4, &tid, sizeof(tid));
		    f->eax = process_wait(tid);
      }
      break;
    case SYS_CREATE: // 4
      {
        char* file;
        unsigned file_size;
        bool success;
        read_mem(f->esp+4, &file, sizeof(file));
        read_mem(f->esp+8, &file_size, sizeof(file_size));
        if((file == NULL) || get_user((const uint8_t*)file) == -1){
		      exit_proc(-1);
	      }
        lock_acquire(&lock_filesys);
        success = filesys_create(file, file_size);
        lock_release(&lock_filesys);
        f->eax = success;
      }
      break;
    case SYS_REMOVE: // 5
      {
        char* file_name;
        bool success;
        read_mem(f->esp+4, &file_name, sizeof(char*));
        lock_acquire(&lock_filesys);
        success = filesys_remove(file_name);
        lock_release(&lock_filesys);
        //if(!success) exit_proc(-1);
        f->eax = success;
      }
      break;
    case SYS_OPEN: // 6
      {
        char* file_name;
        struct file* file;
        read_mem(f->esp+4, &file_name, sizeof(char*));
        if((file_name == NULL) || get_user((const uint8_t*)file_name) == -1){
		      exit_proc(-1);
	      }
        struct fd* file_desc;
#ifdef VM
        file_desc = get_frame()->frame_addr;
#else
        file_desc = palloc_get_page(PAL_USER);
#endif
        if (file_desc == NULL) exit_proc(-1);
        lock_acquire(&lock_filesys);
        file = filesys_open(file_name);
        if(file == NULL) {
          palloc_free_page(file_desc);
          f->eax = -1;
          lock_release(&lock_filesys);
          return;
        }
        file_desc->file = file;
        
        struct list* file_desc_list = &thread_current()->fd_list;
        if(list_empty(file_desc_list)) {
          file_desc->fd_num = 3;
        }
        else {
          file_desc->fd_num = (list_entry(list_back(file_desc_list), struct fd, elem)->fd_num) + 1;
        }
        list_push_back(file_desc_list, &(file_desc->elem));
        lock_release(&lock_filesys);
	      if(file_desc->fd_num == -1) exit_proc(-1);
        f->eax = file_desc->fd_num;
        return;
      }
      break;
    case SYS_FILESIZE: // 7
      {
        int fd;
        int file_size;
        read_mem(f->esp+4, &fd, sizeof(char*));
        lock_acquire(&lock_filesys);
        struct fd* f_desc = get_file_desc(&thread_current()->fd_list, fd);
        if (f_desc == NULL){ 
          file_size = -1;
	      }
        else{
          file_size = file_length(f_desc->file);
	      }
        lock_release(&lock_filesys);
        f->eax = file_size;
      }
      break;
    case SYS_READ: // 8
      {
        int fd;
        void* buff;
        unsigned size;
        read_mem(f->esp + 4, &fd, sizeof(fd));
        read_mem(f->esp + 8, &buff, sizeof(buff));
        read_mem(f->esp + 12, &size, sizeof(size));
        if((buff == NULL) ||!is_user_vaddr(buff)) {
		      exit_proc(-1);
	      }

		 f->eax = read_file(fd, buff, size);
   	  }
      break;
    case SYS_WRITE: // 9
      {
        int fd;
        const void* buff;
        unsigned size;
        read_mem(f->esp + 4, &fd, sizeof(fd));
        read_mem(f->esp + 8, &buff, sizeof(buff));
        read_mem(f->esp + 12, &size, sizeof(size));
        if((buff == NULL) || get_user((const uint8_t *) buff) == -1 || !is_user_vaddr(buff)) {
		      exit_proc(-1);
	      }
        f->eax = write_file(fd, buff, size);
      }
      break;
    case SYS_SEEK: // 10
      {
        int fd;
        unsigned pos;
        read_mem(f->esp + 4, &fd, sizeof(fd));
        read_mem(f->esp + 8, &pos, sizeof(pos));
        lock_acquire(&lock_filesys);
        struct fd* f_desc = get_file_desc(&thread_current()->fd_list, fd);
        if (f_desc == NULL) 
          lock_release(&lock_filesys);
        else 
          file_seek(f_desc->file, pos);
        lock_release(&lock_filesys);
      }
      break;
    case SYS_TELL: // 11
      {
        int fd;
        unsigned pos;
        read_mem(f->esp + 4, &fd, sizeof(fd));
        lock_acquire(&lock_filesys);
        struct fd* f_desc = get_file_desc(&thread_current()->fd_list, fd);
        if (f_desc == NULL) 
          pos = -1;
        else 
          pos = file_tell(f_desc->file);
        lock_release(&lock_filesys);
        //if (!pos) exit_proc(-1);
        f->eax = pos;
      }
      break;
    case SYS_CLOSE: // 12
      {
        int fd;
        read_mem(f->esp + 4, &fd, sizeof(fd));
        close_fd(fd, &thread_current()->fd_list);
      }
      break;
	
	//NEW SYSCALLS FOR FILESYSTEM

	case SYS_CHDIR:		//Changes the current working directory of the process to dir, which may 
						//be relative or absolute. Returns true if successful, false on failure. 
		char *directory;
				
		read_mem(f->esp + 4, &directory, sizeof(directory));
		
		break;	

	case SYS_MKDIR:		//Creates the directory named dir, which may be relative or absolute. Returns true if successful, 
						//false on failure. Fails if dir already exists or if any directory name in dir, besides the last, 
						//does not already exist. That is, mkdir("/a/b/c") succeeds only if /a/b already exists and /a/b/c does not. 

		break;

	case SYS_READDIR:	

		break;

	case SYS_ISDIR:

		break;

	case SYS_INUMBER:

		break;

    default:
        f->eax = -1;
        printf("Unknown SYSCALL, exit\n");  
	      exit_proc(-1); // exit since we do not deal with any of these exit codes yet.
      break;
  }
}



