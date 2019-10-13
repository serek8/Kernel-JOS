#include <kernel/swap/swap.h>
#include <stdio.h>
#include <kernel/mem.h>
#include <task.h>
#include <kernel/dev/disk.h>
#include <kernel/dev/pci.h>
#include <string.h>

#define SWAP_DISC_SIZE  2*PAGE_SIZE
#define SWAP_DISC_INDEX_NUM SWAP_DISC_SIZE / PAGE_SIZE

void rmap_init(struct rmap *map){
    list_init(&map->elems);
}

// todo: Could not allocate page of order 9. Out of memory
struct swap_disk_mapping_t swap_disk_mapping[SWAP_DISC_INDEX_NUM]; // TODO: change 128 to real memsize
void *tmp_ram_backed_disc;

void swap_init(){
    tmp_ram_backed_disc = (void*)(KSTACK_TOP - KSTACK_SIZE);
    for(int i=0; i<SWAP_DISC_INDEX_NUM; i++){
        swap_disk_mapping[i].swap_rmap = NULL;
        swap_disk_mapping[i].is_taken = 0;
    }
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
void read_from_disk(void *addr, uint64_t index);
void write_to_disk(void *addr, uint64_t index);

void rmap_prepare_ptes_for_swap_out(struct page_info *page, uint64_t swap_index){
    struct rmap_elem *elem;
	struct list *node;
    cprintf("rmap_prepare_ptes_for_swap_out:\n");
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        cprintf("  > before updating PTE elem->p_rmap=%p, &pte=%p, pte=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
        *elem->entry &= (~PAGE_PRESENT);
        *elem->entry |= (PAGE_SWAP);
        *elem->entry &= (PAGE_MASK);
        *elem->entry |= PAGE_ADDR(swap_index);
        cprintf("  > after updating PTE elem->p_rmap=%p, &pte=%p, pte=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
    }
}

void rmap_prepare_ptes_for_swap_in(struct page_info *page){
    struct rmap_elem *elem;
	struct list *node;
    cprintf("rmap_prepare_ptes_for_swap_in:\n");
	list_foreach(&page->pp_rmap->elems, node) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        cprintf("  > before updating PTE elem->p_rmap=%p, &pte=%p, pte_before=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
        *elem->entry &= (~PAGE_SWAP);
        *elem->entry |= (PAGE_PRESENT);
        *elem->entry &= (PAGE_MASK);
        *elem->entry |= PAGE_ADDR(page2pa(page));
        cprintf("  > after updating PTE elem->p_rmap=%p, &pte=%p, pte_before=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
    }
}

int swap_out(struct page_info *page){
    cprintf("swap_out page->pp_rmap=%p\n", page->pp_rmap);
    int free_index = find_free_swap_index();
    if(free_index == -1) panic("no more free swap pages!\n");
    struct swap_disk_mapping_t *swap_index_elem = &swap_disk_mapping[free_index];
    page->pp_rmap->pp_ref = page->pp_ref;
    swap_index_elem->swap_rmap = page->pp_rmap;
    swap_index_elem->is_taken = 1;
    write_to_disk(page2kva(page), free_index);
    rmap_prepare_ptes_for_swap_out(page, free_index);

    // clear page_info struct
    page->pp_rmap = NULL;
    page->pp_ref = 0;
    
    return 0;
}

int swap_in(physaddr_t pte){
    uint64_t swap_index = PAGE_ADDR(pte);
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
    read_from_disk(page2kva(page), swap_index);
    rmap_prepare_ptes_for_swap_in(page);
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

void disc_ram_read(void *buf, size_t count, uint64_t addr){
    memcpy(buf, addr+tmp_ram_backed_disc, count);
}

void disc_ram_write(void *buf, size_t count, uint64_t addr){
    memcpy(addr+tmp_ram_backed_disc, buf, count);
}

void read_from_disk(void *addr, uint64_t index){
    disc_ram_read(addr, PAGE_SIZE, index*PAGE_SIZE);
}

void write_to_disk(void *addr, uint64_t index){
    disc_ram_write(addr, PAGE_SIZE, index*PAGE_SIZE);
}

// void save_to_disk_while(){
//     struct disk *disk = disks[1];
//     char buf[PAGE_SIZE];
//     memset(buf, 'B', PAGE_SIZE);

//     int64_t disk_write_res = -1;
//     while(disk_write_res == -1){
//         disk_write_res = disk_write(disk, buf, 8, 0);
//         cprintf("disk_write_res=%d\n", disk_write_res);
//     }
// }

// void read_from_disk_while(){
//     struct disk *disk = disks[1];
//     char buf[PAGE_SIZE];
//     memset(buf, 'A', PAGE_SIZE);
//     int64_t disk_read_res =-1;
//     while(disk_read_res == -1){
//         disk_read_res = disk_read(disk, buf, 2*PAGE_SIZE, 0);
//         cprintf("disk_read_res=%d\n", disk_read_res);
//     }
//     cprintf("read=%s\n", buf);
// }

// void read_from_disk2(){
//     struct disk *disk = disks[1];
//     char buf[PAGE_SIZE];
//     int disk_poll_res = disk_poll(disk);
//     cprintf("disk_poll_res=%d\n", disk_poll_res);
//     int64_t disk_read_res = disk_read(disk, buf, 1, 0);
//     cprintf("disk_read_res=%d\n", disk_read_res);
//     cprintf("read=%s\n", buf);
// }


// void save_to_disk2(){
//     char buf[PAGE_SIZE];
//     char str="dupa";
//     strcpy(buf, str);
//     int nsectors = PAGE_SIZE / SECT_SIZE; /* = 8 */ 
//     ata_start_write(1, nsectors);
//     for (int i = 0; i < nsectors; i++) {
//         while (!ata_is_ready()) /* nothing */;
//         ata_write_sector(buf + i*SECT_SIZE); 
//     }
//     cprintf("saved=%s\n", buf);
// }


void rmap_free(struct rmap *map){
    if(map == NULL){
        return;
    }
    struct rmap_elem *elem;
    struct list *node = NULL, *next = NULL;
    cprintf("rmap_free: removing all rmap elems for the page_info\n");
	list_foreach_safe(&map->elems, node, next) {
		elem = container_of(node, struct rmap_elem, rmap_node);
        cprintf("  > removing elem->p_rmap=%p, &pte=%p, pte=(%p)\n", elem->p_rmap, elem->entry, *elem->entry);
        list_remove(&elem->task_node);
        list_remove(&elem->rmap_node);
        kfree(elem);
    }
    kfree(map);
}

//     char buf[PAGE_SIZE];
//     int nsectors = PAGE_SIZE / SECT_SIZE; /* = 8 */ 
//     ata_start_read(1, nsectors);
//     for (int i = 0; i < nsectors; i++) {
//         while (!ata_is_ready()) /* nothing */;
//         ata_read_sector(buf + i*SECT_SIZE); 
//     }
//     cprintf("read=%s\n", buf);