#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Inserts the given VMA into the red-black tree of the given task. First tries
 * to find a VMA for the end address of the given end address. If there is
 * already a VMA that overlaps, this function returns -1. Then the VMA is
 * inserted into the red-black tree and added to the sorted linked list of
 * VMAs.
 */
int insert_vma(struct task *task, struct vma *vma)
{
	struct rb_node *rb_parent = NULL;
	struct list *node;
	struct vma *found, *parent;
	int dir;

	found = find_vma(&rb_parent, &dir, &task->task_rb, vma->vm_end);

	if (found && found->vm_base < vma->vm_end) {
		return -1;
	}

	parent = rb_parent ? container_of(rb_parent, struct vma, vm_rb) : NULL;
	node = &parent->vm_mmap;

	if (!parent) {
		task->task_rb.root = &vma->vm_rb;
	} else {
		rb_parent->child[dir] = &vma->vm_rb;
		vma->vm_rb.parent = rb_parent;
	}

	if (rb_insert(&task->task_rb, &vma->vm_rb) < 0) {
		return -1;
	}

	if (!parent) {
		list_insert_before(&task->task_mmap, &vma->vm_mmap);
	} else {
		if (dir) {
			list_insert_before(node, &vma->vm_mmap);
		} else { 
			list_insert_after(node, &vma->vm_mmap);
		}
	}

	return 0;
}

/* Allocates and adds a new VMA for the given task.
 *
 * This function first allocates a new VMA. Then it copies over the given
 * information. The VMA is then inserted into the red-black tree and linked
 * list. Finally, this functions attempts to merge the VMA with the adjacent
 * VMAs.
 *
 * Returns the new VMA if it could be added, NULL otherwise.
 */
struct vma *add_executable_vma(struct task *task, char *name, void *addr,
	size_t size, int flags, void *src, size_t len)
{
	/* LAB 4: your code here. */
	struct vma *vma = kmalloc(sizeof(struct vma));
	int name_len = strlen(name);
	vma->vm_name = strcpy(kmalloc(name_len), name);
	vma->vm_name[name_len] = '\0';
	vma->base_offset = addr - ROUNDDOWN(addr, PAGE_SIZE);
	vma->vm_base = ROUNDDOWN(addr, PAGE_SIZE);
 	vma->vm_end = ROUNDUP(addr+size, PAGE_SIZE);
	vma->vm_src = src;
	vma->vm_len = len;
	list_init(&vma->vm_mmap);
	// rb_init(&vma->vm_rb);
	if((flags & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC)){
		panic("VMA cannot be eecutable and writable at the same time!");
	}
	vma->vm_flags = flags;
	if(insert_vma(task, vma) == -1){
		cprintf("insert_vma return -1");
	}
	// TODO merge
	return vma;
}

/* A simplified wrapper to add anonymous VMAs, i.e. VMAs not backed by an
 * executable.
 */
struct vma *add_anonymous_vma(struct task *task, char *name, void *addr,
	size_t size, int flags)
{
	return add_executable_vma(task, name, addr, size, flags, NULL, 0);
}

/* Allocates and adds a new VMA to the requested address or tries to find a
 * suitable free space that is sufficiently large to host the new VMA. If the
 * address is NULL, this function scans the address space from the end to the
 * beginning for such a space. If an address is given, this function scans the
 * address space from the given address to the beginning and then scans from
 * the end to the given address for such a space.
 *
 * Returns the VMA if it could be added. NULL otherwise.
 */
struct vma *add_vma(struct task *task, char *name, void *addr, size_t size,
	int flags)
{
	/* LAB 4: your code here. */
	struct list *node;
	struct list *prev;

	if(addr != NULL) {
		struct vma *vma = find_vma(NULL, NULL, &task->task_rb, addr);
		if((vma->vm_base - addr) > size) {
			cprintf("vma->vm_base=%p, addr=%p\n", vma->vm_base, addr);
			return add_anonymous_vma(task, name, addr, size, flags);
		}

		// TODO: search starting from vma in loop
		return NULL;
	}

	// scan address space from end to beginning
	list_foreach_safe_rev(&task->task_mmap, node, prev) {
		struct vma *vma = container_of(node, struct vma, vm_mmap);
		struct vma *prev_vma = container_of(prev, struct vma, vm_mmap);

		// make sure it's not the first item in the list
		if(prev != &task->task_mmap) {
			// check if there is enough space between vma and prev_vma to create new vma
			if((vma->vm_base - prev_vma->vm_end) > size) {
				cprintf("adding new vma at base=%p, vma->vm_base=%p, prev_vma->vm_end=%p\n", vma->vm_base-size, vma->vm_base, prev_vma->vm_end);
				return add_anonymous_vma(task, name, vma->vm_base-size, size, flags);
			}
		} else {
			panic("TODO: support mapping before first page. vm_name=%s\n", vma->vm_name);
		}
	}

	return NULL;
}

