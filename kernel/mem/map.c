#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

struct boot_map_info {
	struct page_table *pml4;
	uint64_t flags;
	physaddr_t pa;
	uintptr_t base, end;
};

/* Stores the physical address and the appropriate permissions into the PTE and
 * increments the physical address to point to the next page.
 */
static int boot_map_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct boot_map_info *info = walker->udata;

	/* LAB 2: your code here. */
	cprintf("pa=%p, base=%p, end=%p, global_base=%p, global_end=%p\n", info->pa, base, end, info->base, info->end);

	*entry = info->flags | PAGE_ADDR(info->pa);
	info->pa += PAGE_SIZE;

	return 0;
}

/* Stores the physical address and the appropriate permissions into the PDE and
 * increments the physical address to point to the next huge page if the
 * physical address is huge page aligned and if the area to be mapped covers a
 * 2M area. Otherwise this function calls ptbl_split() to split down the huge
 * page or allocate a page table.
 */
static int boot_map_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct boot_map_info *info = walker->udata;

	/* LAB 2: your code here. */
	return 0;
}

/*
 * Maps the virtual address space at [va, va + size) to the contiguous physical
 * address space at [pa, pa + size). Size is a multiple of PAGE_SIZE. The
 * permissions of the page to set are passed through the flags argument.
 *
 * This function is only intended to set up static mappings. As such, it should
 * not change the reference counts of the mapped pages.
 *
 * Hint: this function calls walk_page_range().
 */
void boot_map_region(struct page_table *pml4, void *va, size_t size,
    physaddr_t pa, uint64_t flags)
{
	/* LAB 2: your code here. */
	struct boot_map_info info = {
		.pa = pa,
		.flags = flags,
		.base = ROUNDDOWN((uintptr_t)va, PAGE_SIZE),
		.end = ROUNDUP((uintptr_t)va + size, PAGE_SIZE) - 1,
	};
	struct page_walker walker = {
		.get_pte = boot_map_pte,
		// .get_pde = boot_map_pde,
		.get_pde = ptbl_alloc,
		.get_pml4e = ptbl_alloc,
		.get_pdpte = ptbl_alloc,
		.udata = &info,
	};

	walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);
}

/* This function parses the program headers of the ELF header of the kernel
 * to map the regions into the page table with the appropriate permissions.
 *
 * First creates an identity mapping at the KERNEL_VMA of size BOOT_MAP_LIM
 * with permissions RW-.
 *
 * Then iterates the program headers to map the regions with the appropriate
 * permissions.
 *
 * Hint: this function calls boot_map_region().
 * Hint: this function ignores program headers below KERNEL_VMA (e.g. ".boot").
 */
void boot_map_kernel(struct page_table *pml4, struct elf *elf_hdr)
{
	struct elf_proghdr *prog_hdr =
	    (struct elf_proghdr *)((char *)elf_hdr + elf_hdr->e_phoff);
	uint64_t flags;
	size_t i;

	/* LAB 2: your code here. */

	// identity mapping at the KERNEL_VMA of size BOOT_MAP_LIM * with permissions RW-.
	uint64_t pages_num = BOOT_MAP_LIM / PAGE_SIZE;
	for(uint64_t i = 0; i<pages_num; ++i){
		cprintf("identity mapping at the KERNEL_VMA of size BOOT_MAP_LIM\n");
		// struct page_info *p = pa2page(PADDR((void*)(KERNEL_VMA + (PAGE_SIZE*i))));
		// page_insert(kernel_pml4, p, (void*)KERNEL_VMA + (PAGE_SIZE*i), 0);

		struct page_info *p = pa2page(PADDR((void*)(KERNEL_VMA + (PAGE_SIZE*i))));
		page_insert(kernel_pml4, p, (void*)KERNEL_VMA + (PAGE_SIZE*i), PAGE_PRESENT | PAGE_WRITE);
	}




	// PARSING ELF

	for(uint64_t i = 0; i<elf_hdr->e_phnum; i++){
		struct elf_proghdr hdr = prog_hdr[i];
		// if(hdr.p_va < KERNEL_VMA) continue;
		flags = PAGE_PRESENT;
		if(hdr.p_flags & ELF_PROG_FLAG_EXEC){ // check if segment should be exectuable
			flags &= ~(PAGE_NO_EXEC); 
		} else {
			flags += PAGE_NO_EXEC | PAGE_WRITE;
		}
		cprintf("boot_map_region, flags=%lx, va=%p, pa=%p, size=%u\n", flags, hdr.p_va, hdr.p_pa, hdr.p_filesz);
		boot_map_region(pml4, (void*)hdr.p_va, hdr.p_filesz, hdr.p_pa, flags);
		// boot_map_region(pml4, (void*)hdr.p_pa, hdr.p_filesz, hdr.p_pa, flags);
	}
}

