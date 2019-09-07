#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

struct remove_info {
	struct page_table *pml4;
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
	cprintf("remove_pte\n");
	if(*entry & PAGE_PRESENT){
		*entry = 0; // set PRESENT flag to 0
		struct page_info *page = pa2page(PAGE_ADDR(*entry)); // free the page it was pointing to
		page_decref(page);
	}
	// TODO TLB
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

	return 0;
}

/* Unmaps the range of pages from [va, va + size). */
void unmap_page_range(struct page_table *pml4, void *va, size_t size)
{
	/* LAB 2: your code here. */
	struct remove_info info = {
		.pml4 = pml4,
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
	unmap_page_range(pml4, va, PAGE_SIZE);
}

