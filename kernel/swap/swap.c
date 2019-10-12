#include <kernel/swap/swap.h>
#include <stdio.h>
#include <kernel/mem.h>

void rmap_init(struct rmap *map){
    list_init(&map->elems);
}

void rmap_elem_init(struct rmap_elem *elem){
    list_init(&elem->rmap_node);
    list_init(&elem->task_node);
    elem->entry = NULL;
    elem->p_rmap = NULL;
}

/* address to 'pte' is in kernel address space */
void rmap_add_mapping(struct rmap *map, physaddr_t *pte, struct task *p_task){
    assert((uint64_t)pte > KERNEL_VMA); // make sure PTE is in kernel address space
    struct rmap_elem *map_elem = kmalloc(sizeof(struct rmap));
    rmap_elem_init(map_elem);
    list_push_left(&map->elems, &map_elem->rmap_node);
    list_push_left(&p_task->task_rmap_elems, &map_elem->task_node);
    map_elem->entry = pte; // kernel address space
    map_elem->p_rmap = map;
}

int swap_out(struct page_info *page){
    cprintf("hello from swap_out\n");
    return -1;
}

int swap_in(uint64_t swap_index){
    cprintf("hello from swap_in\n");

    return -1;
}