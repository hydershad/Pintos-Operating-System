#ifndef FRAME_H 
#define FRAME_H 

#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"

struct frame_table_entry {
	tid_t process_id;
	struct sup_pte *spte;
	void *frame_addr;
	bool modify;
};


void frame_init(void);
struct frame_table_entry* get_frame(void);
struct frame_table_entry * eviction(void);
void frame_table_destroy(void);
void frame_table_clear(struct thread *t);
#endif /* vm/frame.h */



