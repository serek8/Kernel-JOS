#include <types.h>
#include <string.h>
#include <paging.h>

#include <kernel/mem.h>
#include <kernel/sched/task.h>
#include <kernel/sched.h>

/* Allocates a page table if none is present for the given entry.
 * If there is already something present in the PTE, then this function simply
 * returns. Otherwise, this function allocates a page using page_alloc(),
 * increments the reference count and stores the newly allocated page table
 * with the PAGE_PRESENT | PAGE_WRITE | PAGE_USER permissions.
 */
int ptbl_alloc(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	/* LAB 2: your code here. */
	if(*entry & PAGE_PRESENT){
		return 0;
	}

	struct page_info *page = page_alloc(ALLOC_ZERO);
	physaddr_t pa = page2pa(page);
	page->pp_ref += 1;
	*entry  = (PAGE_PRESENT | PAGE_WRITE | PAGE_USER | PAGE_ADDR(pa));

	return 0;
}

/* Splits up a huge page by allocating a new page table and setting up the huge
 * page into smaller pages that consecutively make up the huge page.
 *
 * If no huge page was mapped at the entry, simply allocate a page table.
 *
 * Otherwise if a huge page is present, allocate a new page, increment the
 * reference count and have the PDE point to the newly allocated page. This
 * page is used as the page table. Then allocate a normal page for each entry,
 * copy over the data from the huge page and set each PDE.
 *
 * Hint: the only user of this function is boot_map_region(). Otherwise the 2M
 * physical page has to be split down into its individual 4K pages by updating
 * the respective struct page_info structs.
 *
 * Hint: this function calls ptbl_alloc(), page_alloc(), page2pa() and
 * page2kva().
 */
int ptbl_split(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	
	if((*entry & PAGE_SWAP)){
		cprintf("ptbl_split: entry & PAGE_SWAP\n");
		// Swap in, because it's easier to operate on present pages
		swap_in(*entry);
	}

	/* LAB 2: your code here. */
	if((*entry & PAGE_PRESENT) == 0){ // page is not present
		// cprintf("page is not present\n");
		ptbl_alloc(entry, base, end, walker);
		return 0;
	} else if((*entry & (PAGE_PRESENT | PAGE_HUGE)) == (PAGE_PRESENT | PAGE_HUGE)) { // huge page
		cprintf("ptbl_split: page huge page\n");
		// pml4 is the first element in *_info struct
		
		struct page_table *pml4 = (struct page_table*)walker->udata;
		struct page_info *huge_page = pa2page(PAGE_ADDR(*entry));
		uint64_t flags = *entry & PAGE_MASK;
		flags &= ~PAGE_HUGE;
		tlb_invalidate(pml4, (void*)base);
		*entry = 0; // BONUS_LAB3: set entry to 0 to mitigate Foreshadow

		ptbl_alloc(entry, base, end, walker);
		struct page_table *pt = (struct page_table*)KADDR((PAGE_ADDR(*entry)));
		for(int i=0; i<PAGE_TABLE_ENTRIES; i++) {
			struct page_info *p4k = page_alloc(BUDDY_4K_PAGE);
			p4k->pp_ref += 1;

			p4k->pp_rmap = kmalloc(sizeof(struct rmap));
			rmap_init(p4k->pp_rmap);
			rmap_add_mapping(p4k->pp_rmap, &pt->entries[i], cur_task);
			swap_add(p4k); // add to LRU list
			
			pt->entries[i] = flags | PAGE_ADDR(page2pa(p4k));
			memcpy(page2kva(p4k), page2kva(huge_page)+PAGE_SIZE*i, PAGE_SIZE);
		}

		swap_remove(huge_page); // remove from LRU list
		page_decref(huge_page);
		return 0;
	}
	panic("ptbl_split: else?\n");

	return 0;
}

/* Attempts to merge all consecutive pages in a page table into a huge page.
 *
 * First checks if the PDE points to a huge page. If the PDE points to a huge
 * page there is nothing to do. Otherwise the PDE points to a page table.
 * Then this function checks all entries in the page table to check if they
 * point to present pages and share the same flags. If not all pages are
 * present or if not all flags are the same, this function simply returns.
 * At this point the pages can be merged into a huge page. This function now
 * allocates a huge page and copies over the data from the consecutive pages
 * over to the huge page.
 * Finally, it sets the PDE to point to the huge page with the flags shared
 * between the previous pages.
 *
 * Hint: don't forget to free the page table and the previously used pages.
 */
int ptbl_merge(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	/* LAB 2: your code here. */
	if((*entry & (PAGE_PRESENT | PAGE_HUGE)) == (PAGE_PRESENT | PAGE_HUGE)) {
		return 0;
	}

	struct insert_info *info = walker->udata;
	struct page_table *pt = (struct page_table*)KADDR((PAGE_ADDR(*entry)));
	struct page_info *pt_page = pa2page(PAGE_ADDR(*entry));
	uint64_t flags = pt->entries[0] & PAGE_MASK;
	flags &= ~(PAGE_ACCESSED);
	flags &= ~(PAGE_DIRTY);
	for(int i=0; i<PAGE_TABLE_ENTRIES; i++){
		// check if all entries are present
		if(!(pt->entries[i] & PAGE_PRESENT)){ // it also eliminates PAGE_SWAP
			return 0;
		}
		if(pa2page(PAGE_ADDR(pt->entries[i]))->pp_ref != 1){
			// merge if only all pages has one owner. Otherwiese it'd be hard to handle spliting and swapping
			return 0;
		}
		uint64_t entry_flags = pt->entries[i] & PAGE_MASK;
		entry_flags &= ~(PAGE_ACCESSED);
		entry_flags &= ~(PAGE_DIRTY);

		// check if all flags are the same
		if(entry_flags != flags) {
			return 0;
		}
	}

	cprintf("merge\n");
	// now pages in pt can be merged
	// copy data to huge page
	struct page_info *page = page_alloc(ALLOC_HUGE);
	void* page_kva = page2kva(page);
	void* start_addr = (void*)end+1 - HPAGE_SIZE;
	for(int i=0; i<PAGE_TABLE_ENTRIES; i++) {
		memcpy(page_kva + PAGE_SIZE*i, start_addr + PAGE_SIZE*i, PAGE_SIZE);
	}

	// point PDE to newly created huge page
	*entry = flags | PAGE_HUGE | PAGE_ADDR(page2pa(page));
	page->pp_ref++;

	// clear up pages
	for(int i=0; i<PAGE_TABLE_ENTRIES; i++) {
		struct page_info *pte_page = pa2page(PAGE_ADDR(pt->entries[i]));
		swap_remove(pte_page); // remove from LRU list
		// at this point we know that pages are present
		page_decref(pte_page);
		tlb_invalidate(info->pml4, (void*)(start_addr + PAGE_SIZE * i));
	}
	// add swapping for huge page
	page->pp_rmap = kmalloc(sizeof(struct rmap));
	rmap_init(page->pp_rmap);
	rmap_add_mapping(page->pp_rmap, entry, cur_task); //info->taskx
	swap_add(page); // add to LRU list

	page_decref(pt_page);
	return 0;
}

/* Frees up the page table by checking if all entries are clear. Returns if no
 * page table is present. Otherwise this function checks every entry in the
 * page table and frees the page table if no entry is set.
 *
 * Hint: this function calls pa2page(), page2kva() and page_free().
 */
int ptbl_free(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	/* LAB 2: your code here. */
	if(!(*entry & PAGE_PRESENT)){
		return -1; // no page table is present
	}
	
	struct page_table *pt = (struct page_table*)KADDR((PAGE_ADDR(*entry)));
	for(uint64_t i=0; i<PAGE_TABLE_ENTRIES; i++){
		if(pt->entries[i] & PAGE_PRESENT){
			return 0;
		}
	}

	struct page_info *page = pa2page(PAGE_ADDR(*entry));
	page_decref(page);

	*entry = 0; // BONUS_LAB3: set entry to 0 to mitigate Foreshadow
	return 0;
}
