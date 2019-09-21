#include <stdio.h>
#include <task.h>
#include <vma.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Given a task and two VMAs, checks if the VMAs are adjacent and compatible
 * for merging. If they are, then the VMAs are merged by removing the
 * right-hand side and extending the left-hand side by setting the end address
 * of the left-hand side to the end address of the right-hand side.
 */
struct vma *merge_vma(struct task *task, struct vma *lhs, struct vma *rhs)
{
	/* LAB 4: your code here. */
	cprintf("lhs: vm_name=%s, base=%p, end=%p\n", lhs->vm_name, lhs->vm_base, lhs->vm_end);
	cprintf("rhs: vm_name=%s, base=%p, end=%p\n", rhs->vm_name, rhs->vm_base, rhs->vm_end);

	if(lhs->vm_end == rhs->vm_base && lhs->vm_flags == rhs->vm_flags) {
		cprintf("---- adjacent and compatible\n");
		lhs->vm_end = rhs->vm_end;
		remove_vma(task, rhs);
		kfree(rhs);
		return lhs;
	}

	return NULL;
}

/* Given a task and a VMA, this function attempts to merge the given VMA with
 * the previous and the next VMA. Returns the merged VMA or the original VMA if
 * the VMAs could not be merged.
 */
struct vma *merge_vmas(struct task *task, struct vma *vma)
{
	/* LAB 4: your code here. */
	struct vma *prev = container_of(vma->vm_mmap.prev, struct vma, vm_mmap);
	struct vma *next = container_of(vma->vm_mmap.next, struct vma, vm_mmap);
	struct vma *merged = NULL;
	cprintf("vm_name=%s, base=%p, list_start=%p, node=%p, prev=%p, next=%p\n", vma->vm_name, vma->vm_base, &task->task_mmap, vma->vm_mmap, prev->vm_mmap, next->vm_mmap);

	if(&task->task_mmap != &prev->vm_mmap) {
		merged = merge_vma(task, prev, vma);
		if(merged) vma = merged;
	}

	if(&task->task_mmap != &next->vm_mmap) {
		merged = merge_vma(task, vma, next);
		if(merged) vma = merged;
	}
	
	return vma;
}

