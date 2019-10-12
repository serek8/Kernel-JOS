#include <kernel/swap/swap.h>

#include <stdio.h>
#include <kernel/sched.h>
#include <kernel/mem.h>

struct list lru_pages;
// TODO: lock

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

void swap_init()
{
    list_init(&lru_pages);
}

void swap_add(struct page_info *page)
{
    // set second chance value
    page->pp_swap_node.r = 1; 
    list_push_left(&lru_pages, &page->pp_swap_node.n);
    cprintf("add: page=%p, pp_ref=%d, content=%p\n", page, page->pp_ref, *((int*)page2kva(page)));
}

void swap_print_lru()
{
    cprintf("----------\nLRU pages\n\n");
    // cprintf("%p, prev=%p, next=%p\n", &lru_pages,lru_pages.prev, lru_pages.next);
    struct list *node;
    int i = 0;
    list_foreach(&lru_pages, node) {
        struct page_info *page = GET_PAGE_FROM_SWAP_NODE_N(node);

        cprintf("%d: swap_node.r=%d, page=%p, pp_ref=%d, content=%p\n", i, page->pp_swap_node.r, page, page->pp_ref, *((uint8_t*)page2kva(page)));
        // cprintf("node=%p, prev=%p, next=%p\n", node, node->prev, node->next);
        i++;
    }
    cprintf("\n----------\n");
}

/**
 * Get LRU page with second chance / CLOCK algorithm.
 * Iterate over lru_pages, advancing head of list if r=1.
 * If r=0, return page and remove from lru_pages.
 */
struct page_info *swap_clock()
{
    struct page_info *page;
    while(1) {
        page = GET_PAGE_FROM_SWAP_NODE_N(lru_pages.next);
        if(page->pp_swap_node.r == 0) {
            list_pop_left(&lru_pages);
            return page;
        }
        page->pp_swap_node.r = 0;

        // advance head of list
        list_advance_head(&lru_pages);
    }
    return NULL;
}

/**
 * Update lru_pages according to whether pages were accessed by the processor.
 * Iterate over all page_infos in lru_pages. 
 * For every page iterate over all rmap elements.
 * - check if PTE has PAGE_ACCESSED flag -> append to lru_pages, reset second chance
 * - reset PAGE_ACCESSED flag
 */
void swapd_update_lru()
{
    struct list *node, *next, *node_rmap;
    // Save the last element of lru_pages. We're going to append to it on the fly.
    struct list *last = lru_pages.prev;

    list_foreach_safe(&lru_pages, node, next) {
        struct page_info *page = GET_PAGE_FROM_SWAP_NODE_N(node);
        
        int updated = 0;
        // iterate over every element in the rmap
        list_foreach(&page->pp_rmap->elems, node_rmap) {
            struct rmap_elem *rmap_elem = container_of(node_rmap, struct rmap_elem, rmap_node);
            
            cprintf("update_lru: swap_node.r=%d, page=%p, pp_ref=%d, content=%p, task_pid=%d, PTE=%p, accessed=%d\n", 
            page->pp_swap_node.r, page, page->pp_ref, *((uint8_t*)page2kva(page)), 
            rmap_elem->p_task->task_pid, *rmap_elem->entry, (*rmap_elem->entry & PAGE_ACCESSED) == PAGE_ACCESSED);
            
            // if page was accessed -> append to lru_pages, reset second chance
            if(((*rmap_elem->entry & PAGE_ACCESSED) == PAGE_ACCESSED) && !updated) {
                page->pp_swap_node.r = 1;
                list_remove(node);
                list_push_left(&lru_pages, node);
                updated = 1;
            }

            // reset accessed flag
            *rmap_elem->entry &= ~(PAGE_ACCESSED);
        }
        // exit loop once we iterated over every item
        if(node == last) {
            break;
        }
    }
}

void swapd()
{
    while(list_is_empty(&lru_pages)) {
        ksched_yield();
    }
    ksched_yield();

    struct list *node;
    int i = 0;
    list_foreach(&lru_pages, node) {
        struct page_info *page = GET_PAGE_FROM_SWAP_NODE_N(node);

        if(i==3) {
            page->pp_swap_node.r = 0;
            break;
        }
        i++;
    }

    swap_print_lru();
    // swap_clock();
    // swap_print_lru();

    swapd_update_lru();
    swap_print_lru();

    ksched_yield();

    swapd_update_lru();
    swap_print_lru();
}
