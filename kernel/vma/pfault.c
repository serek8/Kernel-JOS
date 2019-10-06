#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>
// #include <kernel/vma/populate.h>

/* Handles the page fault for a given task. */
int task_page_fault_handler(struct task *task, void *va, int flags)
{
	/* LAB 4: your code here. */
	struct vma *vma = find_vma(NULL, NULL, &task->task_rb, va);

	// cprintf("pfault: vma=%p, vm_base=%p\n", vma, vma->vm_base);

	if(!(vma->vm_base <= va && vma->vm_end >= va) || vma->vm_flags == 0) {
		return -1;
	}

	physaddr_t *entry;
	struct page_info *page = page_lookup(task->task_pml4, va, &entry);
	// COW
	if(entry != 0x0 && 
	page != NULL &&
	(*entry & PAGE_WRITE) != (PAGE_WRITE) && 
	(vma->vm_flags & VM_WRITE) == (VM_WRITE)) {
		// cprintf("pfault: COW!\n");

		if(page->pp_ref == 1) {
			*entry |= PAGE_WRITE;
		} else {
			struct page_info *new_page;
			if(*entry & PAGE_HUGE) {
				new_page = page_alloc(BUDDY_2M_PAGE);
				memcpy(page2kva(new_page), page2kva(page), HPAGE_SIZE);
			} else {
				new_page = page_alloc(BUDDY_4K_PAGE);
				memcpy(page2kva(new_page), page2kva(page), PAGE_SIZE);
			}
			++new_page->pp_ref;

			*entry = PAGE_ADDR(page2pa(new_page)) | (*entry & PAGE_MASK);
			*entry |= PAGE_WRITE;
			page_decref(page);
			tlb_invalidate(task->task_pml4, va);
		}
		return 0;
	}

	#ifdef BONUS_LAB5
	// zero-page deduplication
	// check: if read page fault for anonymous vma -> set entry to global zero page from kernel (read-only)
	// and then gets COWed later automatically
	if(((flags & PF_WRITE) != PF_WRITE) && 
	page == NULL &&
	vma->vm_src == NULL) {
		cprintf("pfault: zero page dedup!\n");
		page_insert(task->task_pml4, zero_dedup, va, PAGE_PRESENT | PAGE_USER);
		return 0;
	}
	#endif

	// When set, the page fault was caused by a page-protection violation. 
	// When not set, it was caused by a non-present page.
	if(flags & PF_PRESENT){
		return -1;
	}

	void *page_start = ROUNDDOWN(va, PAGE_SIZE);
	return populate_vma_range(task, page_start, PAGE_SIZE, flags);

	/* LAB 5: your code here. */
	return -1;
}

