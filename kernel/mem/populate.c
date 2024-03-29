#include <types.h>
#include <paging.h>

#include <kernel/mem.h>
#include <kernel/swap/swap.h>

struct populate_info {
	struct page_table *pml4;
	uint64_t flags;
	uintptr_t base, end;
	struct task *taskx;
	int user_page;
};

static int populate_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct page_info *page;
	struct populate_info *info = walker->udata;

	/* LAB 3: your code here. */
	if(*entry & PAGE_PRESENT) {
		struct page_info *old_page = pa2page(PAGE_ADDR(*entry));
		page_decref(old_page);
		*entry = 0; // BONUS_LAB3: set entry to 0 to mitigate Foreshadow
		tlb_invalidate(info->pml4, (void*)base);
	}
	page = page_alloc(ALLOC_ZERO);
	page->pp_ref++;

	*entry = info->flags | PAGE_ADDR(page2pa(page));
	// add reverse mapping (support only user tasks)
	if(info->taskx && info->taskx->task_type == TASK_TYPE_USER){ 
		// cprintf("populate_pte: adding reverse mapping for info->taskx=%p\n", info->taskx);
		page->pp_rmap = kmalloc(sizeof(struct rmap));
		rmap_init(page->pp_rmap);
		rmap_add_mapping(page->pp_rmap, entry, info->taskx);
	}
	if(info->user_page) {
		swap_add(page);
	}

	return 0;
}

static int populate_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct page_info *page;
	struct populate_info *info = walker->udata;

	/* LAB 3: your code here. */
	if((*entry & (PAGE_PRESENT | PAGE_HUGE)) == (PAGE_PRESENT | PAGE_HUGE)) {
		struct page_info *old_page = pa2page(PAGE_ADDR(*entry));
		page_decref(old_page);
		*entry = 0; // BONUS_LAB3: set entry to 0 to mitigate Foreshadow
		tlb_invalidate(info->pml4, (void*)base);
	}

	// huge page
	if(((end-base+1) == HPAGE_SIZE) && hpage_aligned(base)) {
		page = page_alloc(ALLOC_ZERO | ALLOC_HUGE);
		page->pp_ref++;
		*entry = info->flags | PAGE_HUGE | PAGE_ADDR(page2pa(page));
		
		// add reverse mapping (support only user tasks)
		if(info->taskx && info->taskx->task_type == TASK_TYPE_USER){ 
			// cprintf("populate_pte: adding reverse mapping for info->taskx=%p\n", info->taskx);
			page->pp_rmap = kmalloc(sizeof(struct rmap));
			rmap_init(page->pp_rmap);
			rmap_add_mapping(page->pp_rmap, entry, info->taskx);
		}
		if(info->user_page) {
			swap_add(page);
		}
	} else {
		// 4K page -> allocate page table
		ptbl_alloc(entry, base, end, walker);
	}

	return 0;
}

/* Populates the region [va, va + size) with pages by allocating pages from the
 * frame allocator and mapping them.
 */
void populate_region(struct page_table *pml4, void *va, size_t size,
	uint64_t flags, struct task *taskx)
{
	populate_region_user(pml4, va, size, flags, taskx, 0);
}

/* Populates the region [va, va + size) with pages by allocating pages from the
 * frame allocator and mapping them.
 */
void populate_region_user(struct page_table *pml4, void *va, size_t size,
	uint64_t flags, struct task *taskx, int user_page)
{
	/* LAB 3: your code here. */
	if(size == 0) {
		panic("Can't populate with size=0\n");
	}

	struct populate_info info = {
		.flags = flags,
		.base = ROUNDDOWN((uintptr_t)va, PAGE_SIZE),
		.end = ROUNDUP((uintptr_t)va + size, PAGE_SIZE) - 1,
		.pml4 = pml4,
		.taskx = taskx,
		.user_page = user_page,
	};
	struct page_walker walker = {
		.get_pte = populate_pte,
		.get_pde = populate_pde,
		.get_pml4e = ptbl_alloc,
		.get_pdpte = ptbl_alloc,
		.udata = &info,
	};

	// check if PAGE_PRESENT is set
	if(!(flags & PAGE_PRESENT)){
		cprintf("WARNING! Populating without PAGE_PRESENT flag!\n");
	} 

	walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);
}

