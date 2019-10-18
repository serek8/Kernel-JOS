#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

struct protect_info {
	struct page_table *pml4;
	uint64_t flags;
	uintptr_t base, end;
};

/* Changes the protection of the page. Avoid calling tlb_invalidate() if
 * nothing changes at all.
 */
static int protect_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	cprintf("protect_pte base=%p\n", base);
	struct protect_info *info = walker->udata;

	if(*entry & PAGE_SWAP) {
		// cprintf("protect_pte & PAGE_SWAP base=%p\n", base);
		mprotect_swapped_out(entry, info->flags); // change permissions directly on the disk
		tlb_invalidate(info->pml4, (void*)base);
		return 0;
	}
	
	if((*entry & PAGE_MASK) != info->flags) { // check if flags actually change
		// cprintf("protect_pte & PAGE_MASK base=%p\n", base);
		*entry = info->flags | PAGE_ADDR(*entry);
		tlb_invalidate(info->pml4, (void*)base);
	}
	return 0;
}

/* Changes the protection of the huge page, if the page is a huge page and if
 * the range covers the full huge page. Otherwise if the page is a huge page,
 * but if the range does not span an entire huge page, this function calls
 * ptbl_split() to split up the huge page. Avoid calling tlb_invalidate() if
 * nothing changes at all.
 */
static int protect_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct protect_info *info = walker->udata;
	if((*entry & (PAGE_SWAP | PAGE_HUGE)) == (PAGE_SWAP | PAGE_HUGE)) {
		swap_in(*entry);
	}
	/* LAB 3: your code here. */
	if((*entry & (PAGE_PRESENT | PAGE_HUGE)) == (PAGE_PRESENT | PAGE_HUGE)) {
		// covers full huge page
		if((end-base+1) == HPAGE_SIZE) {
			// check if flags actually change
			if((*entry & PAGE_MASK) != info->flags) {
				*entry = info->flags | PAGE_HUGE | PAGE_ADDR(*entry);
				tlb_invalidate(info->pml4, (void*)base);
			}
		} else {
			cprintf("will ptbl_split\n");
			ptbl_split(entry, base, end, walker);
		}
	}

	return 0;
}

/* Changes the protection of the region [va, va + size) to the permissions
 * specified by flags.
 */
void protect_region(struct page_table *pml4, void *va, size_t size,
    uint64_t flags)
{
	/* LAB 3: your code here. */
	struct protect_info info = {
		.pml4 = pml4,
		.flags = flags,
		.base = ROUNDDOWN((uintptr_t)va, PAGE_SIZE),
		.end = ROUNDUP((uintptr_t)va + size, PAGE_SIZE) - 1,
	};
	struct page_walker walker = {
		.get_pte = protect_pte,
		.get_pde = protect_pde,
		.unmap_pde = ptbl_merge,
		.udata = &info,
	};

	walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);
}

