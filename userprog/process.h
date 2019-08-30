#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
typedef int pid_t;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


struct pcb_t {

  pid_t pid;		//child tid
  int load_status;	
  int exit_status;
  int dead; 		//whether thread has been killed or exited normal
  int waiting;	//if process is waiting already
  struct thread *parent;	//pointer to parent thread/process
  struct semaphore load;  //semaphores for load/exit status
  struct semaphore exit;
  struct semaphore p_wait;  //semaphores for process wait and process exec
  struct semaphore p_exec;
  struct list_elem elem;  //structure just like in main threads structure to contain elements
  char* prog_name;
  char* cmd_line;
};

#endif /* userprog/process.h */
