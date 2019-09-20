#include <task.h>
#include <vma.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Removes the given VMA from the given task. */
void remove_vma(struct task *task, struct vma *vma)
{
	if (!task || !vma) {
		return;
	}

	rb_remove(&task->task_rb, &vma->vm_rb);
	rb_node_init(&vma->vm_rb);
	list_remove(&vma->vm_mmap);
}

/* Frees all the VMAs for the given task. */
void free_vmas(struct task *task)
{
	/* LAB 4: your code here. */
	struct vma *vma;
	struct list *node;
	struct list *prev;
	list_foreach_safe(&task->task_mmap, node, prev) {
		vma = container_of(node, struct vma, vm_mmap);
		do_remove_vma(task, vma->vm_base, vma->vm_end-vma->vm_base, vma, NULL);
	}
}

/* Splits the VMA into the address range [base, base + size) and removes the
 * resulting VMA and any physical pages that back the VMA.
 */
int do_remove_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
	/* LAB 4: your code here. */
	cprintf("Removing vma_name=%s, base=%p, size=%d\n", vma->vm_name, base, size);
	if(base == vma->vm_base && base+size == vma->vm_end){  //  [ vma ]
		// cprintf("[ vma ]\n");
		protect_region(task->task_pml4, base, size, 0);
	} else if(base == vma->vm_base){  //  [ vma |   |   ]
		// cprintf("[ vma |    |   ]\n");
		split_vma(task, vma, base+size);
		remove_vma(task, vma);
		protect_region(task->task_pml4, base, size, 0);
	} else if(base + size == vma->vm_end){  //  [   |   |  vma ]
		// cprintf("[   |   | vma ]\n");
		struct vma *rm_vma = split_vmas(task, vma, base, size);
		remove_vma(task, rm_vma);
		protect_region(task->task_pml4, rm_vma->vm_base, rm_vma->vm_end - rm_vma->vm_base, 0);
	} else{  //  [   | vma  |   ]
		// cprintf("[   | vma |   ]\n");
		struct vma *rm_vma = split_vmas(task, vma, base, size);
		remove_vma(task, rm_vma);
		protect_region(task->task_pml4, rm_vma->vm_base, rm_vma->vm_end - rm_vma->vm_base, 0);
	}
	// TODO remove physical pages
	// kfree(vma);
	return 0;
}

/* Removes the VMAs and any physical pages backing those VMAs for the given
 * address range [base, base + size).
 */
int remove_vma_range(struct task *task, void *base, size_t size)
{
	return walk_vma_range(task, base, size, do_remove_vma, NULL);
}

/* Removes any non-dirty physical pages for the given address range
 * [base, base + size) within the VMA.
 */
int do_unmap_vma(struct task *task, void *base, size_t size, struct vma *vma, // TODO roundup size
	void *udata)
{
	/* LAB 4: your code here. */
	cprintf("Unmapping VMA_name=%s, base=%p, size=%d, vma->vm_end=%p\n", vma->vm_name, base, size, vma->vm_end);
	
	cprintf(((vma->vm_flags & VM_DIRTY) == VM_DIRTY) ? "VM_DIRTY\n" : "NOT VM_DIRTY\n" );
	if((vma->vm_flags & VM_DIRTY) == VM_DIRTY){
		return 0;
	}
	do_remove_vma(task, base, size, vma, udata);
	// protect_region(task->task_pml4, base, size, 0);
	return 0;
}

/* Removes any non-dirty physical pages within the address range
 * [base, base + size).
 */
int unmap_vma_range(struct task *task, void *base, size_t size)
{
	return walk_vma_range(task, base, size, do_unmap_vma, NULL);
}

