#include <kernel/swap/swap.h>
#include <stdio.h>
#include <kernel/mem.h>
#include <task.h>

void rmap_init(struct rmap *map){
    list_init(&map->elems);
}


// void rmap_free(struct rmap *map){
//     if(map == NULL){
//         return;
//     }
//     struct rmap_elem *elem;
// 	struct list *node;
//     cprintf("rmap_free: removing all rmap elems\n");
// 	list_foreach(&map->elems, node) {
// 		elem = container_of(node, struct rmap_elem, rmap_node);
//         cprintf("  > removing elem->p_rmap=%p, &pte=%p, pte=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
//         // kfree(elem);
//     }
//     // kfree(map);
// }

void print_task_rmap_elems(struct task *taskx);
void rmap_free_task_rmap_elems(struct list *task_rmap_elems){
    if(task_rmap_elems == NULL){
        panic("shouldnt end up here- rmap_free_task_rmap_elems\n");
        return;
    }
    struct rmap_elem *elem;
	struct list *node = NULL, *next = NULL;

    // cprintf("rmap_free_task_rmap_elems:\n");
    // cprintf("sumup_task\n; * * * * * * * * * \n");
    // elem = container_of(task_rmap_elems->next, struct rmap_elem, task_node);
    // print_task_rmap_elems(elem->p_task);
    // cprintf("end sumup_task\n; * * * * * * * * * \n");
	list_foreach_safe(task_rmap_elems, node, next) {
		elem = container_of(node, struct rmap_elem, task_node);
        cprintf("  > removing: &rmap=%p, &pte=%p, p_task_pid=%d, &p_task=%p\n", elem->p_rmap, elem->entry, elem->p_task->task_pid, elem->p_task);
        list_remove(&elem->task_node);
        list_remove(&elem->rmap_node);
        kfree(elem);
    }
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
    cprintf("rmap_add_mapping: &rmap=%p, pte=%p, p_task_pid=%d, p_task=%p\n", map, pte, p_task->task_pid, p_task);
    struct rmap_elem *map_elem = kmalloc(sizeof(struct rmap_elem));
    rmap_elem_init(map_elem);
    list_push_left(&map->elems, &map_elem->rmap_node);
    list_push_left(&p_task->task_rmap_elems, &map_elem->task_node);
    map_elem->entry = pte; // kernel address space
    map_elem->p_rmap = map;
    map_elem->p_task = p_task;
}

void print_page_info_rmap_elems(struct page_info *page){
    struct rmap_elem *elem;
	struct list *node;
    cprintf("page=%p, page->pp_rmap=%p\n", page, page->pp_rmap);
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        cprintf("  > elem->p_rmap=%p, &pte=%p, pte=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
    }
}

void print_task_rmap_elems(struct task *taskx){
    struct rmap_elem *elem;
	struct list *node;
    cprintf("task_pid=%p, &task=%p\n", taskx->task_pid, taskx);
	list_foreach(&taskx->task_rmap_elems, node) {
		elem = container_of(node, struct rmap_elem, task_node);
        cprintf("  > &p_rmap=%p, &pte=%p, pte=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
    }
}

int swap_out(struct page_info *page){
    cprintf("swap_out: map=%p\n\n* * * * * * * * * *", page->pp_rmap->elems);
    // print_task_rmap_elems();
    cprintf("* * * * * * * * *\n");
    return -1;
}

int swap_in(uint64_t swap_index){
    cprintf("hello from swap_in\n");
    return -1;
}