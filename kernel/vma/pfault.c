#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>
// #include <kernel/vma/populate.h>

/* Handles the page fault for a given task. */
int task_page_fault_handler(struct task *task, void *va, int flags)
{
	/* LAB 4: your code here. */
	//TODO: check access rights
	return populate_vma_range(task, ROUNDDOWN(va, PAGE_SIZE), PAGE_SIZE, flags); // TODO: what if its HUGEPAGE

	/* LAB 5: your code here. */
	return -1;
}

