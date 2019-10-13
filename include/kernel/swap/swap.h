#pragma once

#include <types.h>
#include <list.h>
#include <paging.h>
#include <x86-64/memory.h>
#include <assert.h>

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
};

struct page_info;
struct task;

void swap_init();
int swap_out(struct page_info *page); // returns 0 on success
int swap_in(physaddr_t pte); // returns 0 on success
void rmap_init(struct rmap *map);
void rmap_free(struct rmap *map);
void rmap_free_task_rmap_elems(struct list *task_rmap_elems);
void rmap_add_mapping(struct rmap *map, physaddr_t *pte, struct task *p_task);

void swapd();
void swap_add(struct page_info *page);
