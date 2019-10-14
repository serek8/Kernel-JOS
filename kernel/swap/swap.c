#include <kernel/swap/swap.h>

#include <stdio.h>
#include <kernel/sched.h>
#include <kernel/mem.h>
#include <task.h>
#include <kernel/dev/disk.h>
#include <kernel/dev/pci.h>
#include <string.h>
#include <error.h>

#define SWAP_DISC_SIZE  (1 * MB) // todo: lab7 we need to extend to 128M
#define SWAP_DISC_INDEX_NUM SWAP_DISC_SIZE / PAGE_SIZE


struct list lru_pages;
// TODO: lock

void rmap_init(struct rmap *map){
    list_init(&map->elems);
    map->pp_ref = 0; // will update value on swap operation
}

struct swap_disk_mapping_t *swap_disk_mapping; // TODO: change 128 to real memsize

void swap_init(){
    cprintf("Initializing swap module. Available swap pages: %d. TODO: support 128MB and huge pages\n", SWAP_DISC_INDEX_NUM);
    // cprintf("SIZE=%d, sizeof=%d\n", SWAP_DISC_INDEX_NUM * sizeof(struct swap_disk_mapping_t), sizeof(struct swap_disk_mapping_t));
    assert(SWAP_DISC_INDEX_NUM * sizeof(struct swap_disk_mapping_t) <= PAGE_SIZE);
    swap_disk_mapping = page2kva(page_alloc(ALLOC_ZERO));
    list_init(&lru_pages);
    for(int i=0; i<SWAP_DISC_INDEX_NUM; i++){
        swap_disk_mapping[i].swap_rmap = NULL;
        swap_disk_mapping[i].is_taken = 0;
    }
}

struct swap_disk_mapping_t *get_swap_disk_mapping_by_id(int i){
    return &swap_disk_mapping[i];
}

void print_task_rmap_elems(struct task *taskx);
int find_free_swap_index();


void rmap_free_task_rmap_elems(struct list *task_rmap_elems){
    if(task_rmap_elems == NULL){
        panic("shouldnt end up here- rmap_free_task_rmap_elems\n");
        return;
    }
    struct rmap_elem *elem;
	struct list *node = NULL, *next = NULL;

    // cprintf("rmap_free_task_rmap_elems:\n");
	list_foreach_safe(task_rmap_elems, node, next) {
		elem = container_of(node, struct rmap_elem, task_node);
        // cprintf("  > removing: &rmap=%p, elem->ref=%d, &pte=%p, *pte=%p, page=%p, task_pid=%d\n", elem->p_rmap, elem->p_rmap->pp_ref, elem->entry, *elem->entry, pa2page(PAGE_ADDR((*elem->entry))), elem->p_task->task_pid);
        list_remove(&elem->task_node);
        list_remove(&elem->rmap_node);
        kfree(elem);
    }
}

/* Used by COW to remove the rmap element from the task list. */
/* *map */
void rmap_unlink_task_rmap_elem_by_rmap_obj(struct list *task_rmap_elems, struct rmap *rmap_obj){
    if(task_rmap_elems == NULL){
        panic("shouldnt end up here- rmap_free_task_rmap_elems\n");
        return;
    }
    struct rmap_elem *elem;
	struct list *node = NULL, *next = NULL;
    // cprintf("rmap_unlink_task_rmap_elem_by_rmap_obj:\n");
	list_foreach_safe(task_rmap_elems, node, next) {
		elem = container_of(node, struct rmap_elem, task_node);
        if(elem->p_rmap == rmap_obj){
            // cprintf("  > unlink elem from task: &rmap=%p, elem->ref=%d, &pte=%p, *pte=%p, page=%p, PID=%d\n", elem->p_rmap, elem->p_rmap->pp_ref, elem->entry, *elem->entry, pa2page(PAGE_ADDR((*elem->entry))), elem->p_task->task_pid);
            list_remove(&elem->task_node);
            list_remove(&elem->rmap_node);
            kfree(elem);
        }
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
    // cprintf("rmap_add_mapping: &rmap=%p, &pte=%p, *pte=%p, page=%p, PID=%d\n", map, pte, *pte, pa2page(PAGE_ADDR((*pte))), p_task->task_pid);
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
    // cprintf("page=%p, page->pp_rmap=%p\n", page, page->pp_rmap);
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        // cprintf("  > p_rmap=%p, page=%p, &pte=%p, *pte=%p\n", elem->p_rmap, page, elem->entry, *elem->entry);
    }
}

void print_task_rmap_elems(struct task *taskx){
    struct rmap_elem *elem;
	struct list *node;
    // cprintf("task_pid=%p, &task=%p\n", taskx->task_pid, taskx);
	list_foreach(&taskx->task_rmap_elems, node) {
		elem = container_of(node, struct rmap_elem, task_node);
        // cprintf("  > &p_rmap=%p, &pte=%p, *pte=%p\n", elem->p_rmap, elem->entry, *elem->entry);
    }
}
void read_from_disk(void *addr, uint64_t index);
void write_to_disk(void *addr, uint64_t index);

void rmap_prepare_ptes_for_swap_out(struct page_info *page, uint64_t swap_index){
    struct rmap_elem *elem;
	struct list *node;
    // cprintf("rmap_prepare_ptes_for_swap_out:\n");
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        // cprintf("  > before updating PTE elem->p_rmap=%p, page=%p, &pte=%p, *pte=%p, PID=%d\n", elem->p_rmap, page, elem->entry, *elem->entry, elem->p_task->task_pid);
        *elem->entry &= (~PAGE_PRESENT);
        *elem->entry |= (PAGE_SWAP);
        *elem->entry &= (PAGE_MASK);
        *elem->entry |= PAGE_ADDR(swap_index << PAGE_TABLE_SHIFT);
        // cprintf("  > after updating PTE elem->p_rmap=%p, page=%p, &pte=%p, *pte=%p, PID=%d\n", elem->p_rmap, PAGE_ADDR(*elem->entry), elem->entry, *elem->entry, elem->p_task->task_pid);
    }
}

void rmap_prepare_ptes_for_swap_in(struct page_info *page){
    struct rmap_elem *elem;
	struct list *node;
    // cprintf("rmap_prepare_ptes_for_swap_in:\n");
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);

        // cprintf("  > before updating PTE p_rmap=%p, page=%p, &pte=%p, *pte=%p PID=%d\n", elem->p_rmap, PAGE_ADDR(*elem->entry), elem->entry, *elem->entry, elem->p_task->task_pid);
        *elem->entry &= (~PAGE_SWAP);
        *elem->entry |= (PAGE_PRESENT);
        *elem->entry &= (PAGE_MASK);
        *elem->entry |= PAGE_ADDR(page2pa(page));
        // cprintf("  > after updating PTE p_rmap=%p, page=%p, &pte=%p, *pte=%p, PID=%d\n", elem->p_rmap, page, elem->entry, *elem->entry, elem->p_task->task_pid);
    }
}


void stest();
void disc_ahci_write(struct page_info *page, uint64_t addr);
void disc_ahci_read(struct page_info *page, uint64_t addr);

int swap_out(struct page_info *page){
    if(!page){
        return -1;
    }
    if((uint64_t)page < KPAGES+(KERNEL_LMA/PAGE_SIZE)*sizeof(*page)){ 
        // We should never have page that points below KERNEL_LMA. If it does, it's probably swap index!
        panic("Error! This page seems to be already swapped out!");
    }
    // stest();
    cprintf("swap_out page->pp_rmap=%p, pp_ref=%d\n", page->pp_rmap, page->pp_ref);
    int free_index = find_free_swap_index();
    if(free_index == -1) panic("no more free swap pages!\n");
    struct swap_disk_mapping_t *swap_index_elem = &swap_disk_mapping[free_index];
    page->pp_rmap->pp_ref = page->pp_ref;
    swap_index_elem->swap_rmap = page->pp_rmap;
    swap_index_elem->is_taken = 1;
    disc_ahci_write(page, free_index * PAGE_SIZE);
    rmap_prepare_ptes_for_swap_out(page, free_index);

    // clear page_info struct
    page->pp_rmap = NULL;
    page->pp_ref = 0;
    cprintf("SWAP OUT completed! page=%p\n", page);
    return 0;
}


int swap_in(physaddr_t pte){
    uint64_t swap_index = PAGE_ADDR_TO_SWAP_INDEX(pte);
    cprintf("swap_in *pte=%p, swap_index=%d\n", pte, swap_index);
    if(!(pte & PAGE_SWAP)) {
        cprintf("the PTE is already swapped in\n");
        return -1;
    }
    struct swap_disk_mapping_t *swap_index_elem = &swap_disk_mapping[swap_index];
    struct page_info *page = page_alloc(BUDDY_4K_PAGE);
    page->pp_rmap = swap_index_elem->swap_rmap;
    page->pp_ref = swap_index_elem->swap_rmap->pp_ref;
    // todo: pp_order?
    swap_index_elem->swap_rmap = NULL;
    swap_index_elem->is_taken = 0;
    disc_ahci_read(page, swap_index * PAGE_SIZE);
    rmap_prepare_ptes_for_swap_in(page);
    cprintf("swap_in completed! page_info=%p, pp_ref=%d\n", page, page->pp_ref);
    return 0;
}

int find_free_swap_index(){
    for(int i=0; i<SWAP_DISC_INDEX_NUM; i++){
        if(swap_disk_mapping[i].is_taken == 0){
            return i;
        }
    }
    panic("find_free_swap_index no more free swap pages!\n");
    return -1;
}

void disc_ahci_write(struct page_info *page, uint64_t addr){
    struct disk *disk = disks[1];
    char *buf = page2kva(page);
    int size = 8; // 8*512sectors = PAGE_SIZE
    addr = addr / 512;
    assert(disk_write(disk, buf, size, addr) == -EAGAIN);
    while (!disk_poll(disk));
    int64_t disk_write_res = disk_write(disk, buf, size, addr);
    cprintf("disk_write_res=%d\n", disk_write_res);

}

void disc_ahci_read(struct page_info *page, uint64_t addr){
    struct disk *disk = disks[1];
    char *buf = page2kva(page);
    int size = 8; // 8*512sectors = PAGE_SIZE
    addr = addr / 512;
    assert(disk_read(disk, buf, size, addr)  == -EAGAIN);
    while (!disk_poll(disk));
    int64_t disk_read_res = disk_read(disk, buf, size, addr);
    // cprintf("disk_read_res=%d\n", disk_read_res);
    // cprintf("read=%c, %s\n", buf);
}



void rmap_free(struct rmap *map){
    if(map == NULL){
        return;
    }
    struct rmap_elem *elem;
    struct list *node = NULL, *next = NULL;
    // cprintf("rmap_free: removing all rmap elems for the page_info\n");
	list_foreach_safe(&map->elems, node, next) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        // cprintf("  > removing elem->p_rmap=%p, &pte=%p, pte=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
        list_remove(&elem->task_node);
        list_remove(&elem->rmap_node);
        kfree(elem);
    }
    kfree(map);
}





void swap_add(struct page_info *page)
{
    // set second chance value
    page->pp_swap_node.r = 1; 
    list_push_left(&lru_pages, &page->pp_swap_node.n);
    // cprintf("add: page=%p, pp_ref=%d, content=%p\n", page, page->pp_ref, *((int*)page2kva(page)));
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
