#pragma once

#include <types.h>
#include <list.h>
#include <paging.h>
#include <x86-64/memory.h>
#include <assert.h>
#include <spinlock.h>

#define PAGE_ADDR_TO_SWAP_INDEX(x) (PAGE_ADDR(x) >> PAGE_TABLE_SHIFT)
#define MB (1024*1024)

#define SWAP_SYNC_BACKGROUND 0
#define SWAP_SYNC_DIRECT 1

struct rmap {
    struct list elems;
    uint16_t pp_ref;
    struct spinlock rmap_lock;
};

#define LOCK_RMAP(rmap) do { spin_lock(&rmap->rmap_lock); } while(0)
#define UNLOCK_RMAP(rmap) do { spin_unlock(&rmap->rmap_lock); } while(0)
#define TRY_LOCK_RMAP(rmap) (spin_trylock(&rmap->rmap_lock))

struct rmap_elem {
    struct list rmap_node;
    struct list task_node; // list anchor for task, so that when destorying a task we can kill all its rmap_elements
    physaddr_t *entry; // PTE entry
    struct rmap *p_rmap; // parent rmap
    struct task *p_task; // parent task | just for debuging | remove later
    uint8_t flag_write;
    uint8_t flag_huge;
    uint8_t flag_no_exec;
};

struct swap_disk_mapping_t{
    struct rmap *swap_rmap;    
    volatile uint8_t is_taken;
    uint8_t pp_order;
};

struct page_info;
struct task;

void swap_init();
int swap_out(struct page_info *page, int sync); // returns 0 on success
int swap_in(physaddr_t pte, int sync); // returns 0 on success
void rmap_init(struct rmap *map);
void rmap_free(struct rmap *map);
void rmap_decref_swapped_out(physaddr_t pte);
void rmap_free_task_rmap_elems(struct list *task_rmap_elems);
void rmap_unlink_task_rmap_elem_by_rmap_obj(struct list *task_rmap_elems, struct rmap *rmap_obj);
void rmap_add_mapping(struct rmap *map, physaddr_t *pte, struct task *p_task);
struct swap_disk_mapping_t *get_swap_disk_mapping_by_id(int i);
void mprotect_swapped_out(physaddr_t *pte, uint64_t flags);

void swapd();
void swap_add(struct page_info *page);
void swap_remove(struct page_info *page);
struct page_info *swap_clock();