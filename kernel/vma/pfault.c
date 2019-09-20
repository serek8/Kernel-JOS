#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>
// #include <kernel/vma/populate.h>

/* Handles the page fault for a given task. */
int task_page_fault_handler(struct task *task, void *va, int flags)
{
	/* LAB 4: your code here. */
	//TODO: check access rights
	struct vma *vma = find_vma(NULL, NULL, &task->task_rb, va);
	if(!(vma->vm_base <= va && vma->vm_end >= va)) {
		return -1;
	}

	void *page_start = ROUNDDOWN(va, PAGE_SIZE);
	return populate_vma_range(task, page_start, PAGE_SIZE, flags); // TODO: what if its HUGEPAGE
}

