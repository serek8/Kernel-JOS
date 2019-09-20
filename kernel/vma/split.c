#include <task.h>
#include <vma.h>

#include <kernel/vma.h>
#include <kernel/mem.h>

/* Given a task and a VMA, this function splits the VMA at the given address
 * by setting the end address of original VMA to the given address and by
 * adding a new VMA with the given address as base.
 */
struct vma *split_vma(struct task *task, struct vma *lhs, void *addr) // returns  [  | X ] 
{
	/* LAB 4: your code here. */
	struct vma *rha = add_anonymous_vma(
			task, lhs->vm_name,//, 
			addr, 
			lhs->vm_end - addr, 
			lhs->vm_flags);
	
	rha->vm_src += (addr - lhs->vm_base) - rha->base_offset;
	lhs->vm_end = addr;
	return rha;
}

/* Given a task and a VMA, this function first splits the VMA into a left-hand
 * and right-hand side at address base. Then this function splits the
 * right-hand side or the original VMA, if no split happened, into a left-hand
 * and a right-hand side. This function finally returns the right-hand side of
 * the first split or the original VMA.
 */
struct vma *split_vmas(struct task *task, struct vma *vma, void *base, size_t size) // returns  [ |X| ] or [ | X ]
{
	/* LAB 4: your code here. */
	struct vma *cmva = NULL;
	if(vma->vm_base != base){
		cmva = split_vma(task, vma, base);     // [  vma  | cmva ]
	} else{
		cmva = vma;                            // [  vma = cmva  ]
	}
	struct vma *rmva = split_vma(task, cmva, base+size);
	return cmva;
}

