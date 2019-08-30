#include "page.h"
#include "frame.h"
#include "userprog/pagedir.h"
#include <string.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include <stdio.h>


unsigned spt_hash (const struct hash_elem *e, void* aux UNUSED) {
  const struct supplemental_page_table* spt = hash_entry(e, struct supplemental_page_table, hash_elem);
  return hash_bytes(&spt->upage, sizeof(&spt->upage));
}

bool spt_less (const struct hash_elem *a, const struct hash_elem *b, void* aux UNUSED) {
  const struct supplemental_page_table* spt_a = hash_entry(a, struct supplemental_page_table, hash_elem);
  const struct supplemental_page_table* spt_b = hash_entry(b, struct supplemental_page_table, hash_elem);

  return spt_a->upage < spt_b->upage;
}

bool spt_delete_page(void* page) {
  struct thread* t = thread_current();

  struct supplemental_page_table tmp_spt;
  tmp_spt.upage = page;

  struct hash_elem* p;
  p = hash_delete(&t->spte, &tmp_spt.hash_elem);
  if(p == NULL) return false;
  return true;
}

bool spte_add_filesys_spt(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  struct supplemental_page_table* spt;

  struct thread* t = thread_current();
  spt = get_frame()->frame_addr;
  if(spt == NULL) return false;

  spt->upage = upage;
  spt->pg_loc = FROM_FILESYS;
  spt->writable = writable;
  spt->dirty = false;
  spt->file = file;
  spt->offset = ofs;
  spt->pg_read_bytes = read_bytes;
  spt->pg_zero_bytes = zero_bytes;

  hash_insert(&t->spte, &spt->hash_elem);

  return true;
}

bool spt_install_zero_page(void* page) {
  struct thread* t = thread_current();
  struct supplemental_page_table* spt;

  spt = get_frame()->frame_addr;
  if(spt == NULL) return false;

  spt->upage = page;
  spt->pg_loc = ALL_ZERO;
  spt->writable = true;
  spt->dirty = false;
  spt->offset = PGSIZE;
  hash_insert(&t->spte, &spt->hash_elem);

  return true;
}

bool spt_load_page(void* page) {
  struct thread* t = thread_current();

  struct supplemental_page_table tmp_spt;
  tmp_spt.upage = page;

  struct hash_elem* p;
  p = hash_find(&t->spte, &tmp_spt.hash_elem);

  if (p == NULL) return false;

  struct supplemental_page_table* spt = hash_entry(p, struct supplemental_page_table, hash_elem);
  if(spt == NULL) return false;

  spt->kpage = get_frame()->frame_addr;
  if(spt->kpage == NULL) return false;

  // implement switch for each possible page_instal location;
  switch(spt->pg_loc) {
    case FROM_FILESYS:
      {
        file_seek(spt->file, spt->offset);
        if(file_read(spt->file, spt->kpage, spt->pg_read_bytes) != (int) spt->pg_read_bytes) {
          //free_frame(spt->kpage);
          return false;
        }
        memset(spt->kpage + spt->pg_read_bytes, 0, spt->pg_zero_bytes);
        break;
      }
    case ALL_ZERO:
      {
        memset(spt->kpage, 0, PGSIZE);
        break;
      }
    default: // not handling other cases just yet
      return false;
  }

  return (pagedir_get_page (t->pagedir, spt->upage) == NULL
          && pagedir_set_page (t->pagedir, spt->upage, spt->kpage, spt->writable));
}
