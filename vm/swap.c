#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <bitmap.h>
struct block *swap_slots;
struct lock swap_lock;
static struct bitmap *swap_table;

static void write_slot(struct block * block, size_t start_sector, void * buf);
static void read_slot(struct block * block, size_t start_sector, void * buf);

static size_t SECTORS_PER_SLOT = PGSIZE / BLOCK_SECTOR_SIZE;
static size_t SWAP_TABLE_SIZE;    // number of slots (each slot is one page)




bool swap_init() {
   
   swap_slots = block_get_role (BLOCK_SWAP);	//aquire swap block device
   if (swap_slots == NULL) PANIC ("Error: Cannot get block: BLOCK_SWAP");
   SWAP_TABLE_SIZE = block_size(swap_slots) / SECTORS_PER_SLOT;

  
   swap_table = bitmap_create (SWAP_TABLE_SIZE); //create bitmap to track sectors
   if (swap_table == NULL) return false; //change to panic? memory allocation error
   
   bitmap_set_all (swap_table, true); //initialize all bits in map to 1 for free
	lock_init(&swap_lock);

   return true;
}

void swap_free (size_t slot_index) {
   
	ASSERT(slot_index < SWAP_TABLE_SIZE);
 bool valid = bitmap_test (swap_table, slot_index);
  if (!valid)
    {
      PANIC("Error: Frame not found in swap disk.\n");
    }
   lock_acquire(&swap_lock);
	bitmap_set(swap_table, slot_index, true);
	lock_release(&swap_lock);
}


static void write_slot(struct block * block, size_t start_sector, void * buf) {
   for(size_t i = 0; i < SECTORS_PER_SLOT; i++){		//write to slot
      block_write(block, start_sector + i, buf + (i * BLOCK_SECTOR_SIZE ));
   }
}

static void read_slot(struct block * block, size_t start_sector, void * buf) {
   for(size_t i = 0; i < SECTORS_PER_SLOT; i++){       //read from a slot
      block_read(block, start_sector + i, buf + (i * BLOCK_SECTOR_SIZE));
   }
}



void swap_in (size_t slot_index, void * frame){		//read in from the slot on the disk
   
 bool valid = bitmap_test (swap_table, slot_index);
  if (!valid)
    {
      PANIC("Error: Frame not found in swap disk.\n");
    }
   ASSERT(slot_index < SWAP_TABLE_SIZE);	

lock_acquire(&swap_lock);
   read_slot(swap_slots, slot_index * SECTORS_PER_SLOT, frame);
   bitmap_set(swap_table, slot_index, true); //set as free slot 
lock_release(&swap_lock)
}


size_t swap_out (void *frame){

    //find free space in the swap blocks
    size_t slot_index = bitmap_scan(swap_table, 0, 1, true);  // start at 0, 1 consecutive page
    if (slot_index == BITMAP_ERROR) return SWAP_ERROR;
    lock_acquire(&swap_lock);
	bitmap_set(swap_table, slot_index, false);    			//mark slot as not free 
    write_slot(swap_slots, slot_index * SECTORS_PER_SLOT, frame);		//write a page to the slot
	lock_release(&swap_lock);
    return slot_index;
}

