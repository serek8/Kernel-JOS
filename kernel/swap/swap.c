#include <kernel/swap/swap.h>

#include <stdio.h>
#include <kernel/sched.h>
#include <kernel/mem.h>
#include <task.h>
#include <kernel/dev/disk.h>
#include <kernel/dev/pci.h>
#include <string.h>
#include <error.h>
#include <atomic.h>

#define SWAP_DISC_SIZE  (128 * MB)
#define SWAP_DISC_INDEX_NUM SWAP_DISC_SIZE / PAGE_SIZE
#define SWAPD_SCHEDULE_TIME_BLOCK ((uint64_t)(1000*1000*1000)*2)

extern volatile size_t nuser_tasks;
extern size_t npages;
extern size_t free_pages;


struct list lru_pages;
struct spinlock disk_lock;
struct spinlock lru_lock;

#define LOCK_DISK(disk_lock) do { spin_lock(&disk_lock); } while(0)
#define UNLOCK_DISK(disk_lock) do { spin_unlock(&disk_lock); } while(0)
#define TRY_LOCK_DISK(disk_lock) (spin_trylock(&disk_lock))

#define LOCK_LRU(lru_lock) do { spin_lock(&lru_lock); } while(0)
#define UNLOCK_LRU(lru_lock) do { spin_unlock(&lru_lock); } while(0)
#define TRY_LOCK_LRU(lru_lock) (spin_trylock(&lru_lock))

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
    spin_init(&lru_lock, "lru_lock");
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
    if(p_task == NULL){
        return;
        panic("omit task!\n");
    }
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
void read_from_disk(void *addr, uint64_t index, int sync);
void write_to_disk(void *addr, uint64_t index, int sync);

void rmap_prepare_ptes_for_swap_out(struct page_info *page, uint64_t swap_index){
    struct rmap_elem *elem;
	struct list *node;
    //  cprintf("rmap_prepare_ptes_for_swap_out:\n");
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        // cprintf("  > before updating PTE elem->p_rmap=%p, page=%p, &pte=%p, *pte=%p, PID=%d, swap_index=%d\n", elem->p_rmap, page, elem->entry, *elem->entry, elem->p_task->task_pid, swap_index);

        // wait until the task is interrupted, so we can replace the PTE. In task_run we use load_pml4, so TLB will be flushed
        // while(!TRY_LOCK_TASK_SWAPPER(elem->p_task)) { /*cprintf("waiting for the task [%d] to get sched_yield=%p\n", elem->p_task->task_pid);*/ }
        
        // backup flags
        elem->flag_write = ((*elem->entry & PAGE_WRITE) == PAGE_WRITE);
        elem->flag_no_exec = ((*elem->entry & PAGE_NO_EXEC) == PAGE_NO_EXEC);
        elem->flag_huge = ((*elem->entry & PAGE_HUGE) == PAGE_HUGE);
        
        // update PTE by replacing PRESENT bit with SWAP bit
        *elem->entry &= (~PAGE_PRESENT); // clear PAGE_PRESENT
        *elem->entry |= (PAGE_SWAP);
        *elem->entry &= (PAGE_MASK); // clear all flags
        *elem->entry |= PAGE_ADDR(swap_index << PAGE_TABLE_SHIFT);
        // UNLOCK_TASK_SWAPPER(elem->p_task);
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

        // restore flags
        *elem->entry |= elem->flag_write ? PAGE_WRITE : 0;
        *elem->entry |= elem->flag_no_exec ? PAGE_NO_EXEC : 0;
        *elem->entry |= elem->flag_huge ? PAGE_HUGE : 0;
        // cprintf("  > after updating PTE p_rmap=%p, page=%p, &pte=%p, *pte=%p, PID=%d\n", elem->p_rmap, page, elem->entry, *elem->entry, elem->p_task->task_pid);
    }
}

void swap_decref_task_swap_counter(struct page_info *page){
    struct rmap_elem *elem;
	struct list *node;
    int inc = page->pp_order == BUDDY_4K_PAGE ? 1 : 512;
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        atomic_sub(&elem->p_task->task_swapped_pages, inc);
        atomic_add(&elem->p_task->task_active_pages, inc);
    }
}

void swap_incref_task_swap_counter(struct page_info *page){
    struct rmap_elem *elem;
	struct list *node;
    int inc = page->pp_order == BUDDY_4K_PAGE ? 1 : 512;
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        atomic_add(&elem->p_task->task_swapped_pages, inc);
        atomic_sub(&elem->p_task->task_active_pages, inc);
    }
}

void disc_ahci_write(struct page_info *page, uint64_t addr, int sync);
void disc_ahci_read(struct page_info *page, uint64_t addr, int sync);

int swap_out(struct page_info *page, int sync){
    if(!page){
        return -1;
    }
    // if((uint64_t)page < KPAGES+(KERNEL_LMA/PAGE_SIZE)*sizeof(*page)){ 
    //     // We should never have page that points below KERNEL_LMA. If it does, it's probably swap index!
    //     cprintf("Error! This page seems to be already swapped out! page=%p\n", page);
    // }
    // cprintf("swap_out page->pp_rmap=%p, pp_ref=%d, order=%d\n", page->pp_rmap, page->pp_ref, page->pp_order);
    while(!TRY_LOCK_RMAP(page->pp_rmap)) cprintf("waiting swap_out=%p\n", page->pp_rmap);
    swap_incref_task_swap_counter(page);
    int free_index = find_free_swap_index(page->pp_order);
    if(free_index == -1) {
        UNLOCK_RMAP(page->pp_rmap);
        return -1;
    }
    int iterations = page->pp_order == BUDDY_4K_PAGE ? 1 : 512;
    struct swap_disk_mapping_t *swap_index_elem = &swap_disk_mapping[free_index];
    page->pp_rmap->pp_ref = page->pp_ref;
    swap_index_elem->swap_rmap = page->pp_rmap;
    swap_index_elem->is_taken = 1;
    swap_index_elem->pp_order = page->pp_order;
    rmap_prepare_ptes_for_swap_out(page, free_index);
    disc_ahci_write(page, free_index * PAGE_SIZE, sync);

    // huge pages
    for(int i=1; i<iterations; i++){
        struct page_info *page_i = page+i;
        swap_index_elem = &swap_disk_mapping[free_index + i];
        swap_index_elem->swap_rmap = NULL;
        swap_index_elem->is_taken = 1;
        swap_index_elem->pp_order = 0x2; // error value
        disc_ahci_write(page_i, (free_index + i) * PAGE_SIZE, sync);
    }

    // clear page_info struct
    swap_remove(page);
    UNLOCK_RMAP(page->pp_rmap);
    page->pp_rmap = NULL;
    page->pp_ref = 0;
    // cprintf("SWAP OUT completed! page=%p\n", page);
    return 0;
}


int swap_in(physaddr_t pte, int sync){
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
    disc_ahci_read(page, swap_index * PAGE_SIZE, sync);
    int iterations = page->pp_order == BUDDY_4K_PAGE ? 1 : 512;

    // huge pages
    for(int i=1; i<iterations; i++){
        struct page_info *page_i = page+i;
        swap_index_elem = &swap_disk_mapping[swap_index + i];
        swap_index_elem->swap_rmap = NULL;
        swap_index_elem->is_taken = 0;
        swap_index_elem->pp_order = 0;
        disc_ahci_read(page_i, (swap_index + i) * PAGE_SIZE, sync);
    }
    swap_decref_task_swap_counter(page);
    swap_add(page);
    // cprintf("swap_in completed! page_info=%p, pp_ref=%d\n", page, page->pp_ref);
    UNLOCK_RMAP(page->pp_rmap);
    return 0;
}

int is_consecutive_512_indexes_free(int i){
    int max = i+512;
    for(; i<max; i++){
        if(swap_disk_mapping[i].is_taken == 1 || i == SWAP_DISC_INDEX_NUM){
            return 0;
        }
    }
    return 1;
}

int find_free_swap_index(int order){
    // TODO: check if user task && lock currently held by same core

    while(!TRY_LOCK_DISK(disk_lock)) { /*cprintf("waiting disc_ahci_write\n")*/ }
    for(int i=0; i<SWAP_DISC_INDEX_NUM; i++){
        if(swap_disk_mapping[i].is_taken == 0){
            if(order == BUDDY_2M_PAGE && !is_consecutive_512_indexes_free(i)){
                continue;
            }
            UNLOCK_DISK(disk_lock);
            return i;
        }
    }
    // panic("find_free_swap_index no more free swap pages!\n");
    UNLOCK_DISK(disk_lock);
    return -1;
}

void disc_ahci_write(struct page_info *page, uint64_t addr, int sync){
    while(!TRY_LOCK_DISK(disk_lock));// cprintf("waiting disc_ahci_write\n");
    struct disk *disk = disks[1];
    char *buf = page2kva(page);
    int size = 8; // 8*512sectors = PAGE_SIZE
    addr = addr / 512;
    assert(disk_write(disk, buf, size, addr) == -EAGAIN);
    int poll = disk_poll(disk);
    // cprintf("task_pid=%d, cpu=%d\n", cur_task->task_pid, this_cpu->cpu_id);
    while (!poll){
        if(sync == SWAP_SYNC_BACKGROUND) { 
            // cprintf("async write worked, cpu=%d\n", this_cpu->cpu_id); 
            ksched_yield();
        }
        poll = disk_poll(disk);
    }
    int64_t disk_write_res = disk_write(disk, buf, size, addr);
    // cprintf("disk_write_res=%d\n", disk_write_res);
    UNLOCK_DISK(disk_lock);
}

void disc_ahci_read(struct page_info *page, uint64_t addr, int sync){
    while(!TRY_LOCK_DISK(disk_lock));// cprintf("waiting disc_ahci_read\n");
    struct disk *disk = disks[1];
    char *buf = page2kva(page);
    int size = 8; // 8*512sectors = PAGE_SIZE
    addr = addr / 512;
    assert(disk_read(disk, buf, size, addr)  == -EAGAIN);
    int poll = disk_poll(disk);
    // cprintf("task_pid=%d, cpu=%d\n", cur_task->task_pid, this_cpu->cpu_id);
    while (!poll){
        if(sync == SWAP_SYNC_BACKGROUND) {
            // cprintf("async read worked, cpu=%d\n", this_cpu->cpu_id); 
            ksched_yield();
        }
        poll = disk_poll(disk);
    }
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


void mprotect_swapped_out(physaddr_t *pte, uint64_t flags){
    uint64_t swap_index = PAGE_ADDR_TO_SWAP_INDEX(*pte);
    if(!(*pte & PAGE_SWAP)) {
        panic("the PTE is already swapped in\n");
        return;
    }
    struct swap_disk_mapping_t *swap_index_elem = &swap_disk_mapping[swap_index];
    struct rmap *map = swap_index_elem->swap_rmap;
    while(!TRY_LOCK_RMAP(map)) cprintf("waiting mprotect_swapped_out=%p\n", map);
    struct rmap_elem *elem;
	struct list *node;
    // cprintf("rmap_prepare_ptes_for_swap_in:\n");
	list_foreach(&map->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        if(elem->entry == pte){
            // cprintf("mprotect_swapped_out changed pte on the disk\n");
            elem->flag_write = ((flags & PAGE_WRITE) == PAGE_WRITE);
            elem->flag_no_exec = ((flags & PAGE_NO_EXEC) == PAGE_NO_EXEC);
            elem->flag_huge = ((flags & PAGE_HUGE) == PAGE_HUGE);
        }
        break;
    }
    UNLOCK_RMAP(map);
}




void swap_add(struct page_info *page)
{
    LOCK_LRU(lru_lock);
    // set second chance value
    page->pp_swap_node.r = 1; 
    list_push_left(&lru_pages, &page->pp_swap_node.n);
    // cprintf("lru_added: page=%p, pp_ref=%d, order=%d, content=%p, lru_len=%d\n", page, page->pp_ref, page->pp_order, *((int*)page2kva(page)), list_len(&lru_pages));
    UNLOCK_LRU(lru_lock);
}

void swap_remove(struct page_info *page) 
{
    LOCK_LRU(lru_lock);
    list_remove(&page->pp_swap_node.n);
    // cprintf("lru_removed: page=%p, pp_ref=%d, order=%d, content=%p, lru_len=%d\n", page, page->pp_ref, page->pp_order, *((int*)page2kva(page)), list_len(&lru_pages));
    UNLOCK_LRU(lru_lock);
}

void swap_print_lru()
{
    LOCK_LRU(lru_lock);
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
    UNLOCK_LRU(lru_lock);
}

/**
 * Get LRU page with second chance / CLOCK algorithm.
 * Iterate over lru_pages, advancing head of list if r=1.
 * If r=0, return page and remove from lru_pages.
 */
struct page_info *swap_clock()
{
    LOCK_LRU(lru_lock);
    struct page_info *page;
    while(1) {
        page = GET_PAGE_FROM_SWAP_NODE_N(lru_pages.next);
        if(page->pp_swap_node.r == 0) {
            list_pop_left(&lru_pages);
            UNLOCK_LRU(lru_lock);
            return page;
        }
        page->pp_swap_node.r = 0;

        // advance head of list
        list_advance_head(&lru_pages);
    }
    UNLOCK_LRU(lru_lock);
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
    LOCK_LRU(lru_lock);
    struct list *node, *next, *node_rmap;
    // Save the last element of lru_pages. We're going to append to it on the fly.
    struct list *last = lru_pages.prev;

    list_foreach_safe(&lru_pages, node, next) {
        struct page_info *page = GET_PAGE_FROM_SWAP_NODE_N(node);
        // cprintf("update_lru: swap_node.r=%d, page=%p, pp_ref=%d, content=%p, page->pp_rmap=%p, page->pp_order=%d\n", page->pp_swap_node.r, page, page->pp_ref, *((uint8_t*)page2kva(page)), page->pp_rmap, page->pp_order);
        
        int updated = 0;
        LOCK_RMAP(page->pp_rmap);
        // iterate over every element in the rmap
        list_foreach(&page->pp_rmap->elems, node_rmap) {
            struct rmap_elem *rmap_elem = container_of(node_rmap, struct rmap_elem, rmap_node);
            // cprintf("update_lru: task_pid=%d, PTE=%p, accessed=%d\n",   
            // rmap_elem->p_task->task_pid, *rmap_elem->entry, (*rmap_elem->entry & PAGE_ACCESSED) == PAGE_ACCESSED);

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
        UNLOCK_RMAP(page->pp_rmap);

        // exit loop once we iterated over every item
        if(node == last) {
            break;
        }
    }
    UNLOCK_LRU(lru_lock);
}

void swapd_test()
{
    for(int i=0; i<100; i++) {
        ksched_yield();
    }

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
    swap_clock();
    // swap_print_lru();

    swapd_update_lru();
    swap_print_lru();

    // ksched_yield();

    // swapd_update_lru();
    // swap_print_lru();
}

// only gets activated if <20% memory available
void swapd()
{
    uint64_t last_time = read_tsc();
    while(nuser_tasks - 1) { // do not count this kernel task
        while(free_mem_percent() < 20) {
            if((read_tsc() - last_time) < SWAPD_SCHEDULE_TIME_BLOCK) {
                break;
            }

            swapd_update_lru();

            while(free_mem_percent() < 10) {
                // swap out
                struct page_info *to_swap = swap_clock();
                int result = 0;
                result = swap_out(to_swap, SWAP_SYNC_DIRECT);
                // cprintf("swapd: to_swap=%p, order=%d\n", to_swap, to_swap->pp_order);
                if(result != -1){
                    to_swap->pp_ref = 1;
                    page_decref(to_swap);
                } else {
                    break;
                }
            }

            cprintf("swapd: nuser_tasks=%d, npages=%p, free_pages=%p, percent=%d\n", nuser_tasks, npages, free_pages, free_mem_percent());
            last_time = read_tsc();
        }

        ksched_yield();
    }
}

