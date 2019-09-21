#include <task.h>
#include <vma.h>

#include <kernel/vma.h>
#include <kernel/mem.h>

/* Given a task and a VMA, this function splits the VMA at the given address
 * by setting the end address of original VMA to the given address and by
 * adding a new VMA with the given address as base.
 */
struct vma *split_vma(struct task *task, struct vma *lhs, void *addr) // returns  [  | ret ] 
{
	/* LAB 4: your code here. */
	struct vma *rhs = add_anonymous_vma(
			task, lhs->vm_name,//, 
			addr, 
			lhs->vm_end - addr, 
			lhs->vm_flags);
	
	rhs->vm_src += (addr - lhs->vm_base) - rhs->base_offset;
	lhs->vm_end = addr;
	return rhs;
}

/* Given a task and a VMA, this function first splits the VMA into a left-hand
 * and right-hand side at address base. Then this function splits the
 * right-hand side or the original VMA, if no split happened, into a left-hand
 * and a right-hand side. This function finally returns the right-hand side of
 * the first split or the original VMA.
 */
struct vma *split_vmas(struct task *task, struct vma *vma, void *base, size_t size) // returns  [  |ret|  ] 
{
	/* LAB 4: your code here. */
	struct vma *middle_vma = split_vma(task, vma, base);
	struct vma *rhs = split_vma(task, middle_vma, base+size);
	return middle_vma;
}


// cprintf("remove_vma: vma->vm_base=%p, vma->vm_end=%p, vma->flags=%p, name=%s\n", vma->vm_base, vma->vm_end, vma->vm_flags, vma->vm_name);