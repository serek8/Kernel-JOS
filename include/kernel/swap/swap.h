#pragma once

#include <types.h>
#include <list.h>


struct rmap {
    struct list elements;
    // lock
};

struct rmap_elem {
    struct list rmap_elem_node;
    struct list task_node; // list anchor for task, so that when destorying a task we can kill all its rmap_elements
    physaddr_t *entry; // PTE entry
    struct rmap p_rmap; // parent rmap
};