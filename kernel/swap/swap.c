#include <kernel/swap/swap.h>

#include <stdio.h>
#include <kernel/sched.h>
#include <kernel/mem.h>
#include <task.h>
#include <kernel/dev/disk.h>
#include <kernel/dev/pci.h>
#include <string.h>
#include <error.h>

#define SWAP_DISC_SIZE  (128 * MB)
#define SWAP_DISC_INDEX_NUM SWAP_DISC_SIZE / PAGE_SIZE

struct list lru_pages;
struct spinlock disk_lock;

#define LOCK_DISK(disk_lock) do { spin_lock(&disk_lock); } while(0)
#define UNLOCK_DISK(disk_lock) do { spin_unlock(&disk_lock); } while(0)
#define TRY_LOCK_DISK(disk_lock) (spin_trylock(&disk_lock))


void rmap_init(struct rmap *map){
    // cprintf("rmap_init, rmap=%p\n", map);
    spin_init(&map->rmap_lock, "rmap_lock");
    list_init(&map->elems);
    map->pp_ref = 0; // will update value on swap operation
}

struct swap_disk_mapping_t *swap_disk_mapping;

void swap_init(){
    cprintf("Initializing swap module. Available swap space: %dMB (%d pages).\n", (SWAP_DISC_SIZE/MB), SWAP_DISC_INDEX_NUM);
    assert(SWAP_DISC_INDEX_NUM * sizeof(struct swap_disk_mapping_t) <= HPAGE_SIZE);
    spin_init(&disk_lock, "disk_lock");
    swap_disk_mapping = page2kva(page_alloc(ALLOC_ZERO | ALLOC_HUGE));
    list_init(&lru_pages);
    for(int i=0; i<SWAP_DISC_INDEX_NUM; i++){
        swap_disk_mapping[i].swap_rmap = NULL;
        swap_disk_mapping[i].is_taken = 0;
        swap_disk_mapping[i].pp_order = 0;
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

    // cprintf("rmap_free_task_rmap_elems\n");
	list_foreach_safe(task_rmap_elems, node, next) {
		elem = container_of(node, struct rmap_elem, task_node);
        // cprintf("  > removing: &rmap=%p, elem->ref=%d, &pte=%p, *pte=%p, page=%p, task_pid=%d\n", elem->p_rmap, elem->p_rmap->pp_ref, elem->entry, *elem->entry, pa2page(PAGE_ADDR((*elem->entry))), elem->p_task->task_pid);
        list_remove(&elem->task_node);
        list_remove(&elem->rmap_node);
        kfree(elem);
    }
    // cprintf("rmap_free_task_rmap_elems completed\n");
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
    while(!TRY_LOCK_RMAP(map)) cprintf("waiting rmap_add_mapping=%p\n", map);
    list_push_left(&map->elems, &map_elem->rmap_node);
    UNLOCK_RMAP(map);
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

        // wait until the task is interrupted, so we can replace the PTE. In task_run we use load_pml4, so TLB will be flushed
        while(!TRY_LOCK_TASK_SWAPPER(elem->p_task)) cprintf("waiting for the task [%d] to get sched_yield=%p\n", elem->p_task->task_pid);
        *elem->entry &= (~PAGE_PRESENT);
        *elem->entry |= (PAGE_SWAP);
        *elem->entry &= (PAGE_MASK);
        *elem->entry |= PAGE_ADDR(swap_index << PAGE_TABLE_SHIFT);
        UNLOCK_TASK_SWAPPER(elem->p_task);
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

void swap_decref_task_swap_counter(struct page_info *page){
    struct rmap_elem *elem;
	struct list *node;
    int inc = page->pp_order == BUDDY_4K_PAGE ? 1 : 512;
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        elem->p_task->task_swapped_pages -= inc;
    }
}

void swap_incref_task_swap_counter(struct page_info *page){
    struct rmap_elem *elem;
	struct list *node;
    int inc = page->pp_order == BUDDY_4K_PAGE ? 1 : 512;
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        elem->p_task->task_swapped_pages += inc;
    }
}

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
    // cprintf("swap_out page->pp_rmap=%p, pp_ref=%d\n", page->pp_rmap, page->pp_ref);
    while(!TRY_LOCK_RMAP(page->pp_rmap)) cprintf("waiting swap_out=%p\n", page->pp_rmap);
    swap_incref_task_swap_counter(page);
    int free_index = find_free_swap_index(page->pp_order);
    if(free_index == -1) panic("no more free swap pages!\n");
    int iterations = page->pp_order == BUDDY_4K_PAGE ? 1 : 512;
    struct swap_disk_mapping_t *swap_index_elem = &swap_disk_mapping[free_index];
    page->pp_rmap->pp_ref = page->pp_ref;
    swap_index_elem->swap_rmap = page->pp_rmap;
    swap_index_elem->is_taken = 1;
    swap_index_elem->pp_order = page->pp_order;
    rmap_prepare_ptes_for_swap_out(page, free_index);
    disc_ahci_write(page, free_index * PAGE_SIZE);

    // huge pages
    for(int i=1; i<iterations; i++){
        struct page_info *page_i = page+i;
        swap_index_elem = &swap_disk_mapping[free_index + i];
        swap_index_elem->swap_rmap = NULL;
        swap_index_elem->is_taken = 1;
        swap_index_elem->pp_order = 0x2; // error value
        disc_ahci_write(page_i, (free_index + i) * PAGE_SIZE);
    }

    // clear page_info struct
    UNLOCK_RMAP(page->pp_rmap);
    page->pp_rmap = NULL;
    page->pp_ref = 0;
    // cprintf("SWAP OUT completed! page=%p\n", page);
    return 0;
}


int swap_in(physaddr_t pte){
    uint64_t swap_index = PAGE_ADDR_TO_SWAP_INDEX(pte);
    // cprintf("swap_in *pte=%p, swap_index=%d\n", pte, swap_index);
    if(!(pte & PAGE_SWAP)) {
        cprintf("the PTE is already swapped in\n");
        return -1;
    }
    struct swap_disk_mapping_t *swap_index_elem = &swap_disk_mapping[swap_index];
    int is_huge_page = swap_index_elem->pp_order == BUDDY_2M_PAGE;
    struct page_info *page = page_alloc(is_huge_page ? ALLOC_HUGE : 0);
    page->pp_rmap = swap_index_elem->swap_rmap;
    while(!TRY_LOCK_RMAP(page->pp_rmap)) cprintf("waiting swap_in=%p\n", page->pp_rmap);
    page->pp_ref = swap_index_elem->swap_rmap->pp_ref;
    swap_index_elem->swap_rmap = NULL;
    swap_index_elem->is_taken = 0;
    rmap_prepare_ptes_for_swap_in(page); // todo: lab7 flush
    disc_ahci_read(page, swap_index * PAGE_SIZE);
    int iterations = page->pp_order == BUDDY_4K_PAGE ? 1 : 512;

    // huge pages
    for(int i=1; i<iterations; i++){
        struct page_info *page_i = page+i;
        swap_index_elem = &swap_disk_mapping[swap_index + i];
        swap_index_elem->swap_rmap = NULL;
        swap_index_elem->is_taken = 0;
        swap_index_elem->pp_order = 0;
        disc_ahci_read(page_i, (swap_index + i) * PAGE_SIZE);
    }
    swap_decref_task_swap_counter(page);
    // cprintf("swap_in completed! page_info=%p, pp_ref=%d\n", page, page->pp_ref);
    UNLOCK_RMAP(page->pp_rmap);
    return 0;
}

int is_consecutive_512_indexes_free(int i){
    for(; i<512; i++){
        if(swap_disk_mapping[i].is_taken == 1 || i == SWAP_DISC_INDEX_NUM){
            return 0;
        }
    }
    return 1;
}

int find_free_swap_index(int order){
    while(!TRY_LOCK_DISK(disk_lock)) cprintf("waiting disc_ahci_write\n");
    for(int i=0; i<SWAP_DISC_INDEX_NUM; i++){
        if(swap_disk_mapping[i].is_taken == 0){
            if(order == BUDDY_2M_PAGE && !is_consecutive_512_indexes_free(i)){
                continue;
            }
            UNLOCK_DISK(disk_lock);
            return i;
        }
    }
    panic("find_free_swap_index no more free swap pages!\n");
    UNLOCK_DISK(disk_lock);
    return -1;
}

void disc_ahci_write(struct page_info *page, uint64_t addr){
    while(!TRY_LOCK_DISK(disk_lock));// cprintf("waiting disc_ahci_write\n");
    struct disk *disk = disks[1];
    char *buf = page2kva(page);
    int size = 8; // 8*512sectors = PAGE_SIZE
    addr = addr / 512;
    assert(disk_write(disk, buf, size, addr) == -EAGAIN);
    while (!disk_poll(disk));
    int64_t disk_write_res = disk_write(disk, buf, size, addr);
    // cprintf("disk_write_res=%d\n", disk_write_res);
    UNLOCK_DISK(disk_lock);
}

void disc_ahci_read(struct page_info *page, uint64_t addr){
    while(!TRY_LOCK_DISK(disk_lock));// cprintf("waiting disc_ahci_read\n");
    struct disk *disk = disks[1];
    char *buf = page2kva(page);
    int size = 8; // 8*512sectors = PAGE_SIZE
    addr = addr / 512;
    assert(disk_read(disk, buf, size, addr)  == -EAGAIN);
    while (!disk_poll(disk));
    int64_t disk_read_res = disk_read(disk, buf, size, addr);
    // cprintf("disk_read_res=%d\n", disk_read_res);
    // cprintf("read=%d\n", *(uint64_t*)buf);
    UNLOCK_DISK(disk_lock);
}



void rmap_free(struct rmap *map){
    if(map == NULL){
        return;
    }
    // cprintf("rmap_free: (rmap=%p)\n", map);
    while(!TRY_LOCK_RMAP(map)) cprintf("waiting map=%p\n", map);
    struct rmap_elem *elem;
    struct list *node = NULL, *next = NULL;
	list_foreach_safe(&map->elems, node, next) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        // cprintf("  > removing elem->p_rmap=%p, &pte=%p, pte=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
        list_remove(&elem->task_node);
        list_remove(&elem->rmap_node);
        kfree(elem);
    }
    UNLOCK_RMAP(map);
    kfree(map);
    // cprintf("rmap_free: (rmap=%p) completed\n", map);
}


void rmap_decref_swapped_out(physaddr_t pte){
    uint64_t swap_index = PAGE_ADDR_TO_SWAP_INDEX(pte);
    // cprintf("rmap_decref_swapped_out *pte=%p, swap_index=%d\n", pte, swap_index);
    if(!(pte & PAGE_SWAP)) {
        panic("the PTE is already swapped in\n");
        return;
    }
    struct swap_disk_mapping_t *swap_index_elem = &swap_disk_mapping[swap_index];
    int iterations = swap_index_elem->pp_order == BUDDY_4K_PAGE ? 1 : 512;
    swap_index_elem->swap_rmap->pp_ref--;
    if(swap_index_elem->swap_rmap->pp_ref == 0){
        // cprintf("remove whole from the disk\n");
        rmap_free(swap_index_elem->swap_rmap);
    }
    for(int i=0; i<iterations; i++){
        swap_index_elem = &swap_disk_mapping[swap_index + i];
        swap_index_elem->swap_rmap = NULL;
        swap_index_elem->is_taken = 0;
        swap_index_elem->pp_order = 0;
    }
}





void swap_add(struct page_info *page)
{
    // set second chance value
    page->pp_swap_node.r = 1; 
    list_push_left(&lru_pages, &page->pp_swap_node.n);
    // cprintf("lru_added: page=%p, pp_ref=%d, order=%d, content=%p, lru_len=%d\n", page, page->pp_ref, page->pp_order, *((int*)page2kva(page)), list_len(&lru_pages));
}

void swap_remove(struct page_info *page) 
{
    list_remove(&page->pp_swap_node.n);
    // cprintf("lru_removed: page=%p, pp_ref=%d, order=%d, content=%p, lru_len=%d\n", page, page->pp_ref, page->pp_order, *((int*)page2kva(page)), list_len(&lru_pages));
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
