#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

struct remove_info {
	struct page_table *pml4;
	uint64_t size;
};

/* Removes the page if present by decrement the reference count, clearing the
 * PTE and invalidating the TLB.
 */
static int remove_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct remove_info *info = walker->udata;
	struct page_info *page;

	/* LAB 2: your code here. */
	if(*entry & PAGE_PRESENT){
		struct page_info *page = pa2page(PAGE_ADDR(*entry)); // free the page it was pointing to
		if(page->pp_ref == 1) rmap_free(page->pp_rmap); // toda lab7: lock + pp_ref without locking
		page_decref(page);
		*entry = 0; // BONUS_LAB3: set entry to 0 to mitigate Foreshadow
		tlb_invalidate(info->pml4, (void*)base);
	}
	return 0;
}

/* Removes the page if present and if it is a huge page by decrementing the
 * reference count, clearing the PDE and invalidating the TLB.
 */
static int remove_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct remove_info *info = walker->udata;
	struct page_info *page;

	/* LAB 2: your code here. */
	if((*entry & (PAGE_PRESENT | PAGE_HUGE)) == (PAGE_PRESENT | PAGE_HUGE)){
		// if we are deleting the complete huge page, remove it immediately
		if(info->size == HPAGE_SIZE) {
			struct page_info *page = pa2page(PAGE_ADDR(*entry)); // free the page it was pointing to
			
			page_decref(page);
			*entry = 0; // BONUS_LAB3: set entry to 0 to mitigate Foreshadow
			tlb_invalidate(info->pml4, (void*)base);
		} else {
			// split huge page if we are deleting a smaller range
			// extract pa and flags from entry
			physaddr_t pa = PAGE_ADDR(*entry);
			uint64_t flags = *entry & PAGE_MASK;
			flags &= ~(PAGE_HUGE);
			
			// create page table and set as entry instead of huge page
			*entry = 0; // BONUS_LAB3: set entry to 0 to mitigate Foreshadow
			tlb_invalidate(info->pml4, (void*)base);
			ptbl_alloc(entry, base, end, walker);
			struct page_table *pt = (struct page_table*)KADDR((PAGE_ADDR(*entry)));

			// create page table entries with same flags
			for(int i=0; i<PAGE_TABLE_ENTRIES; i++) {
				physaddr_t page4k_pa = pa + PAGE_SIZE*i;
				pt->entries[i] = flags | PAGE_ADDR(page4k_pa);
				struct page_info *page = pa2page(page4k_pa);
				page->pp_order = BUDDY_4K_PAGE;
				page->pp_free = 0;
				page->pp_ref = 1; // TODO: this feels especially hacky
			}
		}
	}

	return 0;
}

/* Unmaps the range of pages from [va, va + size). */
void unmap_page_range(struct page_table *pml4, void *va, size_t size)
{
	/* LAB 2: your code here. */
	struct remove_info info = {
		.pml4 = pml4,
		.size = size,
	};
	struct page_walker walker = {
		.get_pte = remove_pte,
		.get_pde = remove_pde,
		.unmap_pte = ptbl_free,
		.unmap_pde = ptbl_free,
		.unmap_pdpte = ptbl_free,
		.unmap_pml4e = ptbl_free,
		
		.udata = &info,
	};

	walk_page_range(pml4, va, va + size, &walker);
}

/* Unmaps all user pages. */
void unmap_user_pages(struct page_table *pml4)
{
	unmap_page_range(pml4, 0, USER_LIM);
}

/* Unmaps the physical page at the virtual address va. */
void page_remove(struct page_table *pml4, void *va)
{
	uint64_t size = PAGE_SIZE;
	struct page_info *page = page_lookup(pml4, va, NULL);
	if(page->pp_order == BUDDY_2M_PAGE) {
		size = HPAGE_SIZE;
	}
	
	unmap_page_range(pml4, va, size);
}

