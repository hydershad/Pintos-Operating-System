#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/syscall.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define LOGGING_LEVEL 6

#include "lib/log.h"

#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

static void child_proc_init(struct pcb_t* pcb_proc) {
  pcb_proc->load_status = -1;
  pcb_proc->exit_status = -1;
  pcb_proc->dead = 0;
  pcb_proc->waiting = 0;
  sema_init(&pcb_proc->load, 0);
  sema_init(&pcb_proc->exit, 0);
  sema_init(&pcb_proc->p_wait, 0);
  sema_init(&pcb_proc->p_exec, 0);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  tid_t tid;

  // NOTE:
  // To see this print, make sure LOGGING_LEVEL in this file is <= L_TRACE (6)
  // AND LOGGING_ENABLE = 1 in lib/log.h
  // Also, probably won't pass with logging enabled.
  log(L_TRACE, "Started process execute: %s", file_name);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  struct pcb_t* child_proc = palloc_get_page(PAL_ZERO);
  if (child_proc == NULL) {
    palloc_free_page(child_proc->cmd_line);
    return TID_ERROR;
  }
  child_proc_init(child_proc);
  child_proc->cmd_line = palloc_get_page(PAL_ZERO);

  if (child_proc->cmd_line == NULL) {
    palloc_free_page(child_proc);
    return TID_ERROR;
  }
  strlcpy (child_proc->cmd_line, file_name, PGSIZE);
  char* save_ptr = (char*) file_name;
  child_proc->prog_name = strtok_r(save_ptr, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (child_proc->prog_name, PRI_DEFAULT, start_process, child_proc);
  sema_down(&child_proc->load);
  if(child_proc->load_status != 1) return TID_ERROR;
  child_proc->pid = tid;
  if (tid == TID_ERROR){
    palloc_free_page(child_proc->cmd_line);
    palloc_free_page(child_proc);
  }
  list_push_back(&thread_current()->pcb_list, &child_proc->elem);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *pcb_t_)
{
  struct pcb_t* pcb = pcb_t_;
  struct intr_frame if_;
  bool success;

  log(L_TRACE, "start_process()");

  /* Initialize interrupt frame and load executable. */
  thread_current()->pcb = pcb;
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (pcb->cmd_line, &if_.eip, &if_.esp);

  /* If load failed, quit. */
#ifdef VM
  //free_frame(pcb->cmd_line);
#else
  palloc_free_page (pcb->cmd_line);
#endif
  if (!success) {
    sema_up(&thread_current()->pcb->load);
    pcb->load_status = -1;
    exit_proc(-1);
  }
  pcb->load_status = 1;
  sema_up(&thread_current()->pcb->load);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  int cp_exit;		//exit status of child porcess
  struct pcb_t *cp;	//child process pointer
  struct thread *current_thread = thread_current(); //thread pointer
  struct list *child = &(current_thread->pcb_list);

  struct list_elem *i;	//list_element pointer to get child process

  for(i = list_begin(child); i !=list_end(child); i = list_next(i)){
	  cp = list_entry(i, struct pcb_t, elem);
	  if(cp->pid == child_tid) 
      break;
	  if(i == list_end(child)) 
      return -1; //child tid does not belong to curernt process
  }


  if(cp->waiting) 
    return -1; //process wait already called
  else 
    cp->waiting = 1;
       //set flag to indicate process is now waiting
  sema_down(&(cp->p_wait));

  if(cp->dead)
    return -1;
  
  cp_exit = cp->exit_status;		//get exit status
  list_remove(i);				//remove child from parent
#ifdef VM
  //free_frame(cp);     	//free the child pcb block
#else
  palloc_free_page(cp);     	//free the child pcb block
#endif
  return cp_exit;			//return child process exit condition
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  sema_up(&cur->pcb->p_wait);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char* exec_args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  log(L_TRACE, "load()");
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();
  char* cmd_tokens;
  cmd_tokens = palloc_get_page(PAL_ZERO);
  strlcpy(cmd_tokens, (char*) file_name, PGSIZE);
  char* save_ptr = (char*) file_name;
  char* fn_exec = strtok_r(save_ptr, " ", &save_ptr);

  /* Open executable file. */
  file = filesys_open (fn_exec);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", fn_exec);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", fn_exec);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, cmd_tokens))
    goto done;
#ifdef VM
  //free_frame(cmd_tokens);
#else
  palloc_free_page(cmd_tokens);
#endif
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  file_deny_write(file);
  thread_current()->exec_file = file;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  log(L_TRACE, "load_segment()");

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM
      ASSERT (pagedir_get_page(thread_current()->pagedir, upage) == NULL); // Check if upage is a virtual page, fail if not
      if (!spte_add_filesys_spt(file, ofs, upage, read_bytes, zero_bytes, writable))
        return false;
#else
      /* Get a page of memory. */
#ifdef VM
      uint8_t *kpage = get_frame()->frame_addr;
#else
      uint8_t *kpage = palloc_get_page (PAL_USER);
#endif
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
#ifdef VM
          //free_frame (kpage);
#else
          palloc_free_page (kpage);
#endif
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
#ifdef VM
          //free_frame (kpage);
#else
          palloc_free_page (kpage);
#endif
          return false;
        }
#endif

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
#ifdef VM
      ofs += PGSIZE;
#endif
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack_args (void** esp, const char* exec_args) {
  char* save_ptr = (char*) exec_args;
  char* token;
  int byte_size = 0;
  int num = 0;
  char** argv_ptrs = palloc_get_page(0);

  if(argv_ptrs == NULL) {
    printf("Error in args stack\n");
    return false;
  }
  while((token = strtok_r(NULL, " ", &save_ptr))) {
    byte_size += strlen(token) + 1;
    if(byte_size >= PGSIZE) {
      palloc_free_page(argv_ptrs);
      return false;
    }
    *esp -= strlen(token) + 1;
    memcpy(*esp, token, strlen(token)+1);
    argv_ptrs[num] = *esp;
    num++;
  }
  argv_ptrs[num] = 0;

  int i = (size_t) *esp % 4;
  *esp -= i;
  if(i) 
    memcpy (*esp, &argv_ptrs[num], i);
  for(int i = num; i >= 0; i--) {
    *esp -= sizeof(char*);
    memcpy(*esp, &argv_ptrs[i], sizeof(char*));
  }
  token = *esp;
  *esp -= sizeof(char**);
  memcpy(*esp, &token, sizeof(char*));
  *esp -= sizeof(int);
  memcpy(*esp, &num, sizeof(int));
  *esp -= sizeof(void *);
  memcpy(*esp, &argv_ptrs[num], sizeof(void*));
#ifdef VM
      //free_frame(argv_ptrs);
#else
      palloc_free_page(argv_ptrs);
#endif
  return true;
}

static bool
setup_stack (void **esp, const char* exec_args)
{
  uint8_t *kpage;
  bool success = false;
  bool arg_stack = false;

  log(L_TRACE, "setup_stack()");

#ifdef VM
  kpage = get_frame()->frame_addr;
#else
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
#endif

  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
        *esp = PHYS_BASE;
        arg_stack = setup_stack_args(esp, exec_args);
	  }
      else {
#ifdef VM
        //free_frame (kpage);
#else
        palloc_free_page (kpage);
#endif
	  }
	  //hex_dump( *(int*)esp, *esp, 256, true ); // NOTE: uncomment this to check arg passing
    }
  return success && arg_stack;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
