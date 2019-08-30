//swap.h
#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool swap_init(void);
void swap_free (size_t slot_index);
size_t swap_out (void *frame);
void swap_in (size_t slot_index, void * frame);
struct frame_table_entry *frame_swap(struct frame_table_entry *fte);


#endif
