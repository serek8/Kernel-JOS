#include <types.h>
#include <boot.h>
#include <list.h>
#include <paging.h>

#include <x86-64/asm.h>

#include <kernel/mem.h>
#include <kernel/tests.h>

extern struct list page_free_list[];

/* The kernel's initial PML4. */
struct page_table *kernel_pml4;

static uintptr_t sign_extend2(uintptr_t addr)
{
	return (addr < USER_LIM) ? addr : (0xffff000000000000ull | addr);
}

/* This function sets up the initial PML4 for the kernel. */
int pml4_setup(struct boot_info *boot_info)
{
	struct page_info *page;

	/* Allocate the kernel PML4. */
	page = page_alloc(ALLOC_ZERO);

	if (!page) {
		panic("unable to allocate the PML4!");
	}

	kernel_pml4 = page2kva(page);

	/* Map in the regions used by the kernel from the ELF header passed to
	 * us through the boot info struct.
	 */

	/* Use the physical memory that 'bootstack' refers to as the kernel
	 * stack. The kernel stack grows down from virtual address KSTACK_TOP.
	 * Map 'bootstack' to [KSTACK_TOP - KSTACK_SIZE, KSTACK_TOP).
	 */

	for(int i=0; i<KSTACK_SIZE; i+=PAGE_SIZE) {
		void *base_va = (void*)KSTACK_TOP-KSTACK_SIZE;
		void *new_va_addr = (void *)sign_extend2(((uint64_t)base_va)+i);
		cprintf("creating stack for cr3, va=%p ==> pa=%p\n", new_va_addr, (void*)(bootstack+i));
		// page_insert(kernel_pml4, pa2page((physaddr_t)bootstack+i), new_va_addr, PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC);
		page_insert(kernel_pml4, pa2page((physaddr_t)bootstack+i), bootstack+KERNEL_VMA+i, PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC);
	}
	// add guard page
	void *base_va = (void*)KSTACK_TOP-KSTACK_SIZE-PAGE_SIZE;
	page_insert(kernel_pml4, NULL, base_va, PAGE_WRITE | PAGE_NO_EXEC);
	// TODO: check PTSIZE

	// setting kernel pages
	// dump_page_tables(kernel_pml4, PAGE_HUGE);
	cprintf("==== setting kernel pages ====\n");
	boot_map_kernel(kernel_pml4, boot_info->elf_hdr);
	cprintf("==== setting kernel pages END ====\n");

	/* Migrate the struct page_info structs to the newly mapped area using
	 * buddy_migrate().
	 */
	// buddy_migrate();

	return 0;
}

/*
 * Set up a four-level page table:
 * kernel_pml4 is its linear (virtual) address of the root
 *
 * This function only sets up the kernel part of the address space (i.e.
 * addresses >= USER_TOP). The user part of the address space will be set up
 * later.
 *
 * From USER_TOP to USER_LIM, the user is allowed to read but not write.
 * Above USER_LIM, the user cannot read or write.
 */
void mem_init(struct boot_info *boot_info)
{
	struct mmap_entry *entry;
	uintptr_t highest_addr = 0;
	uint32_t cr0;
	size_t i, n;

	/* Align the areas in the memory map. */
	align_boot_info(boot_info);

	/* Set up the page free lists. */
	for (i = 0; i < BUDDY_MAX_ORDER; ++i) {
		list_init(page_free_list + i);
	};

	/* Find the amount of pages to allocate structs for. */
	entry = (struct mmap_entry *)((physaddr_t)boot_info->mmap_addr);

	for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {
		if (entry->type != MMAP_FREE)
			continue;

		highest_addr = entry->addr + entry->len;
	}

	/* Limit the struct page_info array to the first 8 MiB, as the rest is
	 * still not accessible until lab 2.
	 */
	npages = MIN(BOOT_MAP_LIM, highest_addr) / PAGE_SIZE;
	cprintf("npages = %d\n", npages);
	/* Remove this line when you're ready to test this function. */
	// panic("mem_init: This function is not finished\n");

	/*
	 * Allocate an array of npages 'struct page_info's and store it in 'pages'.
	 * The kernel uses this array to keep track of physical pages: for each
	 * physical page, there is a corresponding struct page_info in this array.
	 * 'npages' is the number of physical pages in memory.  Your code goes here.
	 */
	pages = boot_alloc(npages * sizeof(struct page_info));
	cprintf("pages = %p\n", pages);
	cprintf("pages = %p\n", boot_alloc(0));
	/*
	 * Now that we've allocated the initial kernel data structures, we set
	 * up the list of free physical pages. Once we've done so, all further
	 * memory management will go through the page_* functions. In particular, we
	 * can now map memory using boot_map_region or page_insert.
	 */
	page_init(boot_info);

	/* We will set up page tables here in lab 2. */

	/* Setup the initial PML4 for the kernel. */
	pml4_setup(boot_info);

	/* Enable the NX-bit. */
	// write_msr(MSR_EFER, MSR_EFER_NXE);

	/* Check the kernel PML4. */
	// lab2_check_pml4();

	/* Load the kernel PML4. */
	// return;
	write_cr3(PADDR(((void *)kernel_pml4)));
	// load_pml4(kernel_pml4);
	return;
	
	/* Check the paging functions. */
	lab2_check_paging();

	/* Add the rest of the physical memory to the buddy allocator. */
	page_init_ext(boot_info);

	/* Check the buddy allocator. */
	lab2_check_buddy(boot_info);
}

/*
 * Initialize page structure and memory free list. After this is done, NEVER
 * use boot_alloc() again. After this function has been called to set up the
 * memory allocator, ONLY the buddy allocator should be used to allocate and
 * free physical memory.
 */
void page_init(struct boot_info *boot_info)
{
	struct page_info *page;
	struct mmap_entry *entry;
	uintptr_t pa, end;
	size_t i;

	/* Go through the array of struct page_info structs and:
	 *  1) call list_init() to initialize the linked list node.
	 *  2) set the reference count pp_ref to zero.
	 *  3) mark the page as in use by setting pp_free to zero.
	 *  4) set the order pp_order to zero.
	 */
	for (i = 0; i < npages; ++i) {
		/* LAB 1: your code here. */
		list_init(&pages[i].pp_node);
		pages[i].pp_ref = 0;
		pages[i].pp_order = 0;
		pages[i].pp_free = 0;
		#ifdef BONUS_LAB1
		pages[i].canary = PAGE_CANARY;
		#endif
	}
	// cprintf("boot_info->mmap_addr = %p\n", boot_info->mmap_addr);
	// cprintf("Kernel boot_info->mmap_addr = %p\n", KADDR(boot_info->mmap_addr));
	entry = (struct mmap_entry *)KADDR(boot_info->mmap_addr);
	// we need to update 'end' because boot_alloc used space beyond kernel area
	end = PADDR(boot_alloc(0));

	show_boot_mmap(boot_info); // #REMOVE#

	/* Go through the entries in the memory map:
	 *  1) Ignore the entry if the region is not free memory.
	 *  2) Iterate through the pages in the region.
	 *  3) If the physical address is above BOOT_MAP_LIM, ignore.
	 *  4) Hand the page to the buddy allocator by calling page_free() if
	 *     the page is not reserved.
	 *
	 * What memory is reserved?
	 *  - Address 0 contains the IVT and BIOS data.
	 *  - boot_info->elf_hdr points to the ELF header.
	 *  - Any address in [KERNEL_LMA, end) is part of the kernel.
	 */

	/* LAB 1: your code here. */
	for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {
		if(entry->type != MMAP_FREE){
			continue;
		}
		physaddr_t pa;
		for (pa = entry->addr; pa < entry->addr + entry->len; pa += PAGE_SIZE){
			if (pa >= BOOT_MAP_LIM){ // We mapped only 8 bytes
				continue;
			}
			struct page_info *page = pa2page(pa);

			// Condition #1
			if (pa == 0){
				continue;
			}

			// Condition #2
			if (pa == PAGE_ADDR(PADDR(boot_info)) || 
				(PAGE_ADDR(boot_info->mmap_addr) <= pa && 
				    pa <= PAGE_ADDR(boot_info->mmap_addr+sizeof(struct mmap_entry)*boot_info->mmap_len)  
				) || 
				pa == (uintptr_t)boot_info->elf_hdr){
					continue;
			}

			// Condition #3
			if (KERNEL_LMA <= pa && pa < end) {
				continue;
			}
			page_free(page);
		}
	}
}

/* Extend the buddy allocator by initializing the page structure and memory
 * free list for the remaining available memory.
 */
void page_init_ext(struct boot_info *boot_info)
{
	struct page_info *page;
	struct mmap_entry *entry;
	uintptr_t pa, end;
	size_t i;

	entry = (struct mmap_entry *)KADDR(boot_info->mmap_addr);
	end = PADDR(boot_alloc(0));

	/* Go through the entries in the memory map:
	 *  1) Ignore the entry if the region is not free memory.
	 *  2) Iterate through the pages in the region.
	 *  3) If the physical address is below BOOT_MAP_LIM, ignore.
	 *  4) Hand the page to the buddy allocator by calling page_free().
	 */
	for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {
		/* LAB 2: your code here. */
	}
}

