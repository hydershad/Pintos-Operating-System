#ifndef VM_PAGE_H
#define VM_PAGE_H
#define STACKSIZE (1 << 13)

#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "lib/kernel/hash.h"
/* Denotes where current page is */
enum page_loc {
  FROM_FILESYS, /* Frome a file or executable */
  IN_FRAME,   /* Is already in memory */
  SWAP,     /* Swapped out */
  ALL_ZERO /* Initialized */
};

struct supplemental_page_table {
  uint8_t* kpage; /* Kernel page associated with it */
  uint8_t* upage; /* Virtual address */

  enum page_loc pg_loc;
  bool writable;  /* Is page writable */
  bool dirty;     /* Has page been modified */

  struct file* file;
  off_t offset;
  size_t pg_read_bytes;
  size_t pg_zero_bytes;
  struct hash_elem hash_elem;
};

unsigned spt_hash(const struct hash_elem *e, void* aux);
bool spt_less(const struct hash_elem* a, const struct hash_elem *b, void* aux);

bool spte_add_filesys_spt(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
bool spt_install_zero_page(void* esp);
bool spt_load_page(void* fault_page);
bool spt_delete_page(void* page);

#endif /* vm/page.h */
