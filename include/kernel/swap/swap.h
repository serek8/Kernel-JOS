#pragma once

#include <types.h>
#include <list.h>
#include <paging.h>
#include <x86-64/memory.h>
#include <assert.h>

#define PAGE_ADDR_TO_SWAP_INDEX(x) (PAGE_ADDR(x) >> PAGE_TABLE_SHIFT)
#define MB 1024*1024

struct rmap {
    struct list elems;
    uint16_t pp_ref;
    // lock
};

struct rmap_elem {
    struct list rmap_node;
    struct list task_node; // list anchor for task, so that when destorying a task we can kill all its rmap_elements
    physaddr_t *entry; // PTE entry
    struct rmap *p_rmap; // parent rmap
    struct task *p_task; // parent task | just for debuging | remove later
};

struct swap_disk_mapping_t{
    struct rmap *swap_rmap;    
    uint8_t is_taken;
    // done add anymore fields because 128M/PAGE_SIZE * this_struct cant be bigger than PAGE_SIZE.
    // It is hard to maintain bigger array(swap_disk_mapping).
};

struct page_info;
struct task;

void swap_init();
int swap_out(struct page_info *page); // returns 0 on success
int swap_in(physaddr_t pte); // returns 0 on success
void rmap_init(struct rmap *map);
void rmap_free(struct rmap *map);
void rmap_free_task_rmap_elems(struct list *task_rmap_elems);
void rmap_unlink_task_rmap_elem_by_rmap_obj(struct list *task_rmap_elems, struct rmap *rmap_obj);
void rmap_add_mapping(struct rmap *map, physaddr_t *pte, struct task *p_task);
struct swap_disk_mapping_t *get_swap_disk_mapping_by_id(int i);

void swapd();
void swap_add(struct page_info *page);
