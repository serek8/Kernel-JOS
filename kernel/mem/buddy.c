#include <types.h>
#include <list.h>
#include <paging.h>
#include <string.h>

#include <kernel/mem.h>

/* Physical page metadata. */
size_t npages;
struct page_info *pages;

/* Lists of physical pages. */
struct list page_free_list[BUDDY_MAX_ORDER];

/* Counts the number of free pages for the given order.
 */
size_t count_free_pages(size_t order)
{
	struct list *node;
	size_t nfree_pages = 0;

	if (order >= BUDDY_MAX_ORDER) {
		return 0;
	}

	list_foreach(page_free_list + order, node) {
		++nfree_pages;
	}

	return nfree_pages;
}

/* Shows the number of free pages in the buddy allocator as well as the amount
 * of free memory in kiB.
 *
 * Use this function to diagnose your buddy allocator.
 */
void show_buddy_info(void)
{
	struct page_info *page;
	struct list *node;
	size_t order;
	size_t nfree_pages;
	size_t nfree = 0;

	cprintf("Buddy allocator:\n");

	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		nfree_pages = count_free_pages(order);

		cprintf("  order #%u pages=%u\n", order, nfree_pages);

		nfree += nfree_pages * (1 << (order + 12));
	}

	cprintf("  free: %u kiB\n", nfree / 1024);
}

/* Gets the total amount of free pages. */
size_t count_total_free_pages(void)
{
	struct page_info *page;
	struct list *node;
	size_t order;
	size_t nfree_pages;
	size_t nfree = 0;

	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		nfree_pages = count_free_pages(order);
		nfree += nfree_pages * (order + 1);
	}

	return nfree;
}

/* Splits lhs into free pages until the order of the page is the requested
 * order req_order.
 *
 * The algorithm to split pages is as follows:
 *  - Given the page of order k, locate the page and its buddy at order k - 1.
 *  - Decrement the order of both the page and its buddy.
 *  - Mark the buddy page as free and add it to the free list.
 *  - Repeat until the page is of the requested order.
 *
 * Returns a page of the requested order.
 */
 struct page_info *buddy_split(struct page_info *lhs, size_t req_order)
{
	/* LAB 1: your code here. */
	if(lhs->pp_order-1 != req_order){
		return buddy_split(lhs, lhs->pp_order-1);
	}
	list_remove(&lhs->pp_node);
	physaddr_t lhs_pa = page2pa(lhs);
	struct page_info *phs = pa2page(lhs_pa ^ ORDER_TO_SIZE(req_order));
	lhs->pp_order -= 1;
	phs->pp_order -= 1;
	list_push(&page_free_list[req_order], &phs->pp_node);
	return lhs;
}

/* Merges the buddy of the page with the page if the buddy is free to form
 * larger and larger free pages until either the maximum order is reached or
 * no free buddy is found.
 *
 * The algorithm to merge pages is as follows:
 *  - Given the page of order k, locate the page with the lowest address
 *    and its buddy of order k.
 *  - Check if both the page and the buddy are free and whether the order
 *    matches.
 *  - Remove the page and its buddy from the free list.
 *  - Increment the order of the page.
 *  - Repeat until the maximum order has been reached or until the buddy is not
 *    free.
 *
 * Returns the largest merged free page possible.
 */
struct page_info *buddy_merge(struct page_info *page)
{
	/* LAB 1: your code here. */
	struct list *node;
	uint64_t order = page->pp_order;
	if(page->pp_order == BUDDY_MAX_ORDER-1){
		return page;
	}
	list_foreach(&page_free_list[page->pp_order], node) {
		struct page_info *page_buddy = container_of(node, struct page_info, pp_node);
		physaddr_t page_pa = page2pa(page);
		physaddr_t page_buddy_pa = page2pa(page_buddy);
		physaddr_t page_buddy_correct_pa = page_pa ^ ORDER_TO_SIZE(order);
		if(page_buddy_pa == page_buddy_correct_pa){ // Found correct buddies
			struct page_info *l_page = page_pa < page_buddy_pa ? page : page_buddy;
			struct page_info *p_page = page_pa < page_buddy_pa ? page_buddy : page;

			// Remove the page_buddy from the page_free_list because we'll increase its order
			list_remove(&page_buddy->pp_node);
			l_page->pp_order += 1;
			p_page->pp_order += 1;
			return buddy_merge(l_page);
		}
	}
	// Going beyond list_foreach means that no buddy page was found	
	return page;
}

/* Given the order req_order, attempts to find a page of that order or a larger
 * order in the free list. In case the order of the free page is larger than the
 * requested order, the page is split down to the requested order using
 * buddy_split().
 *
 * Returns a page of the requested order or NULL if no such page can be found.
 */
struct page_info *buddy_find(size_t req_order)
{
	/* LAB 1: your code here. */
	size_t order;
	struct page_info *page;
	struct list *node;
	list_foreach(page_free_list + req_order, node) {
		return container_of(node, struct page_info, pp_node);
	}
	if(req_order >= BUDDY_MAX_ORDER-1){
		return NULL;
	}
	return buddy_split(buddy_find(req_order+1), req_order);
}

/*
 * Allocates a physical page.
 *
 * if (alloc_flags & ALLOC_ZERO), fills the entire returned physical page with
 * '\0' bytes.
 * if (alloc_flags & ALLOC_HUGE), returns a huge physical 2M page.
 *
 * Beware: this function does NOT increment the reference count of the page -
 * this is the caller's responsibility.
 *
 * Returns NULL if out of free memory.
 *
 * Hint: use buddy_find() to find a free page of the right order.
 * Hint: use page2kva() and memset() to clear the page.
 */
struct page_info *page_alloc(int alloc_flags)
{
	/* LAB 1: your code here. */
	uint64_t order = (alloc_flags & ALLOC_HUGE) ? BUDDY_2M_PAGE : BUDDY_4K_PAGE; 
	struct page_info *page = buddy_find(order);
	assert(page != NULL);
	page->pp_free = 0;
	list_remove(&page->pp_node);

	#ifdef BONUS_LAB1
	uint8_t *page_ka = page2kva(page);
	for(unsigned int i = 0; i<ORDER_TO_SIZE(page->pp_order); i++){
		if(page_ka[i] != POISON_BYTE) {
			panic("Use-after-free detection");
		}
	}
	#endif

	if(alloc_flags & ALLOC_ZERO){
		void *page_ka = page2kva(page);
		memset(page_ka, '\0', ORDER_TO_SIZE(order));
	}
	return page;
}

/*
 * Return a page to the free list.
 * (This function should only be called when pp->pp_ref reaches 0.)
 *
 * Hint: mark the page as free and use buddy_merge() to merge the free page
 * with its buddies before returning the page to the free list.
 */
void page_free(struct page_info *pp)
{
	/* LAB 1: your code here. */
	#ifdef BONUS_LAB1
	// double free
	if(pp->pp_free == 0x1) panic("double free");

	// use-after-free
	memset(page2kva(pp), POISON_BYTE, ORDER_TO_SIZE(pp->pp_order));
	#endif
	
	pp->pp_free = 0x1;
	pp = buddy_merge(pp);
	list_push(&page_free_list[pp->pp_order], &pp->pp_node); 
}

/*
 * Decrement the reference count on a page,
 * freeing it if there are no more refs.
 */
void page_decref(struct page_info *pp)
{
	if (--pp->pp_ref == 0) {
		page_free(pp);
	}
}

static int in_page_range(void *p)
{
	return ((uintptr_t)pages <= (uintptr_t)p &&
	        (uintptr_t)p < (uintptr_t)(pages + npages));
}

static void *update_ptr(void *p)
{
	if (!in_page_range(p))
		return p;

	return (void *)((uintptr_t)p + KPAGES - (uintptr_t)pages);
}

void buddy_migrate(void)
{
	struct page_info *page;
	struct list *node;
	size_t i;

	for (i = 0; i < npages; ++i) {
		page = pages + i;
		node = &page->pp_node;

		node->next = update_ptr(node->next);
		node->prev = update_ptr(node->prev);
	}

	for (i = 0; i < BUDDY_MAX_ORDER; ++i) {
		node = page_free_list + i;

		node->next = update_ptr(node->next);
		node->prev = update_ptr(node->prev);
	}

	pages = (struct page_info *)KPAGES;
}

int buddy_map_chunk(struct page_table *pml4, size_t index)
{
	struct page_info *page, *base;
	void *end;
	size_t nblocks = (1 << (12 + BUDDY_MAX_ORDER - 1)) / PAGE_SIZE;
	size_t nalloc = ROUNDUP(nblocks * sizeof *page, PAGE_SIZE) / PAGE_SIZE;
	size_t i;

	index = ROUNDDOWN(index, nblocks);
	base = pages + index;
	
	for (i = 0; i < nalloc; ++i) {
		page = page_alloc(ALLOC_ZERO);

		if (!page) {
			return -1;
		}

		++page->pp_ref;

		if (page_insert(pml4, page, (char *)base + i * PAGE_SIZE,
		    PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC) < 0) {
			return -1;
		}
	}

	for (i = 0; i < nblocks; ++i) {
		page = base + i;
		list_init(&page->pp_node);
	}

	npages = index + nblocks;

	return 0;
}

