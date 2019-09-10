#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

struct protect_info {
	struct page_table *pml4;
	uint64_t flags;
	uintptr_t base, end;
};

/* Stores the physical address and the appropriate permissions into the PTE and
 * increments the physical address to point to the next page.
 */
static int protect_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct protect_info *info = walker->udata;

	/* LAB 3: your code here. */
	return 0;
}

/* Stores the physical address and the appropriate permissions into the PDE and
 * increments the physical address to point to the next huge page if the
 * physical address is huge page aligned and if the area to be protectped covers a
 * 2M area. Otherwise this function calls ptbl_split() to split down the huge
 * page or allocate a page table.
 */
static int protect_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct protect_info *info = walker->udata;

	/* LAB 3: your code here. */
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
		.udata = &info,
	};

	walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);
}

