#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Checks the flags in udata against the flags of the VMA to check appropriate
 * permissions. If the permissions are all right, this function populates the
 * address range [base, base + size) with physical pages. If the VMA is backed
 * by an executable, the data is copied over. Then the protection of the
 * physical pages is adjusted to match the permissions of the VMA.
 */

int do_populate_vma(struct task *task, void *base, size_t size,
	struct vma *vma, void *udata)
{
	/* LAB 4: your code here. */
	// TODO: uint64_t int_flags = *(uint8_t*)udata;
	// uint64_t int_flags_vma = VM_READ;
	// int_flags_vma += (int_flags & PF_IFETCH) ? VM_EXEC : 0;
	// int_flags_vma += (int_flags & PF_WRITE) ? VM_WRITE : 0;
	// if(vma->vm_flags & VM_DIRTY){
	// 	cprintf("VM_DIRTY !!!\n");
	// }
	// if(int_flags_vma != vma->vm_flags){
	// 	cprintf("int_flags_vma=%p | vma->vm_flags=%p\n", int_flags_vma, vma->vm_flags);
	// 	return -1;
	// }
	
	populate_region(task->task_pml4, base, size, PAGE_PRESENT | PAGE_WRITE);		
	if (vma->vm_src){
		memcpy(vma->vm_base, vma->vm_src, MIN(size, vma->vm_len)); // fix src, index todo
	}
	uint64_t pt_flags = PAGE_PRESENT | PAGE_USER;
	pt_flags += (vma->vm_flags & VM_EXEC) ? 0 : PAGE_NO_EXEC;
	pt_flags += (vma->vm_flags & VM_WRITE) ? PAGE_WRITE : 0;
	cprintf("do_populate_vma: base=%p, size=%d, page_flags=%x, name=%s\n", base, size, pt_flags, vma->vm_name);
	protect_region(task->task_pml4, base, size, pt_flags);
	return 0;
}

/* Populates the VMAs for the given address range [base, base + size) by
 * backing the VMAs with physical pages.
 */
int populate_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_populate_vma, &flags);
}

