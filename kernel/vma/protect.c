#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>
#include <include/lib.h>

/* Changes the protection flags of the given VMA. Does nothing if the flags
 * would remain the same. Splits up the VMA into the address range
 * [base, base + size) and changes the protection of the physical pages backing
 * the VMA. Then attempts to merge the VMAs in case the protection became the
 * same as that of any of the adjacent VMAs.
 */
int do_protect_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
	/* LAB 4 (bonus): your code here. */
	int new_flags = *(int*)udata;

	// R--, RW-, R-X, RWX
	if(!((new_flags == PROT_READ) ||
		(new_flags == PROT_NONE) ||
		(new_flags == (PROT_READ + PROT_WRITE)) ||
		(new_flags == (PROT_READ + PROT_EXEC)) ||
		(new_flags == (PROT_READ + PROT_WRITE + PROT_EXEC)))
	) {
		return -1;
	}
	if((uint64_t)base+size >= USER_LIM || base == NULL){
		cprintf("!!! do_protect_vma: Managmenent of addresses above %p is not allowed!\n", USER_LIM);
		return -1;
	}
	if(vma->vm_flags == new_flags){
		cprintf("!!! do_protect_vma: flags are the same!\n");
		return 0;
	}

	if(base == vma->vm_base && base+size == vma->vm_end){  //  [ vma ]
	} else if(base == vma->vm_base){                       //  [ vma |     ]
		split_vma(task, vma, base+size);
	} else if(base + size == vma->vm_end){                 //  [    |  vma ]
		vma = split_vma(task, vma, base);
	} else{                                                //  [   | vma  |   ]
		vma = split_vmas(task, vma, base, size);
	}

	uint64_t vma_flags = 0;
	vma_flags |= (new_flags & PROT_READ) ? VM_READ : 0;
	vma_flags |= (new_flags & PROT_WRITE) ? VM_WRITE : 0;
	vma_flags |= (new_flags & PROT_EXEC) ? VM_EXEC : 0;
	vma->vm_flags = vma_flags;

	uint64_t page_flags = 0;
	page_flags |= (new_flags == PROT_NONE) ? 0 : (PAGE_PRESENT | PAGE_USER);
	page_flags |= (new_flags & PROT_WRITE) ? PAGE_WRITE : 0;
	page_flags |= (new_flags & PROT_EXEC) ? 0 : PAGE_NO_EXEC;
	// cprintf("vma->vm_base=%p, vma->vm_end=%p, vma->name=%s, page_flags=%x\n", vma->vm_base, vma->vm_end, vma->vm_name, page_flags);
	protect_region(task->task_pml4, base, size, page_flags);
	merge_vmas(task, vma);
	return 0;
}

/* Changes the protection flags of the VMAs for the given address range
 * [base, base + size).
 */
int protect_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_protect_vma, &flags);
}

