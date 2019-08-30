#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include <stdio.h>
//total user pages() in palloc.c/.


struct frame_table_entry *frame_table;
struct lock frame_lock;

void frame_init(void){
  lock_init(&frame_lock);
  int user_pages = userpage_count();
  frame_table = (struct frame_table_entry *)(malloc(sizeof(struct frame_table_entry) * user_pages));

  void *f_ptr;
  int i = 0;
  for (i = 0; i < userpage_count(); i++)
  {
    f_ptr = palloc_get_page(PAL_USER);
    frame_table[i].frame_addr = f_ptr; 
    frame_table[i].process_id = -1;		//set to negative value so we know its free/not in use
    frame_table[i].spte = NULL;
    frame_table[i].modify = false; //if it is being modified by a thread/in use
  }

}

struct frame_table_entry *get_frame(void){		//get first free/unused frame
  lock_acquire(&frame_lock);
  int i;
  for (i = 0; i < userpage_count(); i++) {
    if (frame_table[i].process_id == -1){
      frame_table[i].spte = NULL;
      frame_table[i].process_id = thread_current()->tid;
      frame_table[i].modify = true;
      lock_release(&frame_lock); 
      return &frame_table[i];
    }
  }
  //if no free frames, evict a frame
  struct frame_table_entry *evict_f = eviction();
  evict_f->spte = NULL;
  evict_f->modify = true;
  lock_release(&frame_lock);
  return evict_f;
}

struct frame_table_entry *eviction(void){
  tid_t curr_tid = thread_current()->tid;

  // look for frames owned by current thread
  int i;
  for (i = 0; i < userpage_count(); i++){
    if (frame_table[i].process_id != curr_tid && !frame_table[i].modify){		//TODO : ADD IS STACK TO SPTE STRUCT
        return frame_swap(&frame_table[i]);			//found a frame not owned by the thread that is not being edited, do a swap
    }
  }

  // If every frame is owned by the current thread, evict one from the thread
  for(i = userpage_count() -1; i > 0; --i) {
    if(!frame_table[i].modify){
        return frame_swap(&frame_table[i]);
    }
  }
}

void frame_table_destroy(void){

  int i;
  for (i = 0; i < userpage_count(); i++)
  {
    palloc_free_page (frame_table[i].frame_addr);
  }
  //lock_release(&frame_lock);
}



void frame_table_clear(struct thread *t){

  lock_acquire (&frame_lock);
  int i;
  for (i = 0; i < userpage_count(); i++)
  {
    if (frame_table[i].process_id == t->tid)
    {
      frame_table[i].process_id = -1;
      frame_table[i].spte = NULL;
    }
  }
  lock_release(&frame_lock);
}

struct frame_table_entry *frame_swap(struct frame_table_entry *fte){
  struct supplemental_page_table *evicted_spte = fte->spte;
/*	struct thread *evicted_thread = thread_get(fte->owner_tid);
	if (evicted_thread){
      pagedir_clear_page(evicted_thread->pagedir, evicted_spte->user_vaddr);
	}
*/
  //evicted_spte->in_swap = true; 
  //evicted_spte->swap_table_index = swap_out(fte);
  /*if (evicted_spte->swap_table_index == -1){
      PANIC ("Swap full\n");
    }*/

//  evicted_spte->valid = false;
  fte->process_id = thread_current()->tid;

	return fte;
}


