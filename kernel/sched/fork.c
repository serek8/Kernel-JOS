#include <error.h>
#include <list.h>

#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

extern struct list runq;
extern pid_t pid_max;
extern struct task **tasks;

struct page_info *copy_ptbl(physaddr_t *entry)
{
	struct page_table *orig_ptbl = (struct page_table*)KADDR(PAGE_ADDR(*entry));
	struct page_info *page = page_alloc(BUDDY_4K_PAGE | ALLOC_ZERO);
	++page->pp_ref;
	struct page_table *clone_ptbl = page2kva(page);

	for(int i=0; i<PAGE_TABLE_ENTRIES; i++) {
		if(orig_ptbl->entries[i]) {
			clone_ptbl->entries[i] = orig_ptbl->entries[i];

			// set to read only for COW
			orig_ptbl->entries[i] &= ~(PAGE_WRITE);
			clone_ptbl->entries[i] &= ~(PAGE_WRITE);

			// increase refcount
			struct page_info *entry_page = pa2page(PAGE_ADDR(orig_ptbl->entries[i]));
			++entry_page->pp_ref;

			// cprintf("ptbl - i=%d, orig_entry=%p, clone_entry=%p, orig_flags=%p, clone_flags=%p\n", 
			// i, 
			// orig_ptbl->entries[i], 
			// clone_ptbl->entries[i],
			// orig_ptbl->entries[i] & PAGE_MASK,
			// clone_ptbl->entries[i] & PAGE_MASK);
		}
	}

	return page;
}

struct page_info *copy_pdir(physaddr_t *entry)
{
	struct page_table *orig_pdir = (struct page_table*)KADDR(PAGE_ADDR(*entry));
	struct page_info *page = page_alloc(BUDDY_4K_PAGE | ALLOC_ZERO);
	++page->pp_ref;
	struct page_table *clone_pdir = page2kva(page);

	for(int i=0; i<PAGE_TABLE_ENTRIES; i++) {
		if(orig_pdir->entries[i]) {
			if(orig_pdir->entries[i] & PAGE_HUGE) {
				clone_pdir->entries[i] = orig_pdir->entries[i];

				// set to read only for COW
				orig_pdir->entries[i] &= ~(PAGE_WRITE);
				clone_pdir->entries[i] &= ~(PAGE_WRITE);
				
				// increase refcount
				struct page_info *entry_page = pa2page(PAGE_ADDR(orig_pdir->entries[i]));
				++entry_page->pp_ref;
			} else {
				struct page_info *ptbl_page = copy_ptbl(&orig_pdir->entries[i]);
				clone_pdir->entries[i] = PAGE_ADDR(page2pa(ptbl_page)) | (orig_pdir->entries[i] & PAGE_MASK);
			}

			// cprintf("pdir - i=%d, orig_entry=%p, clone_entry=%p, orig_flags=%p, clone_flags=%p\n", 
			// i, 
			// orig_pdir->entries[i], 
			// clone_pdir->entries[i],
			// orig_pdir->entries[i] & PAGE_MASK,
			// clone_pdir->entries[i] & PAGE_MASK);
		}
	}

	return page;
}

struct page_info *copy_pdpt(physaddr_t *entry) 
{
	struct page_table *orig_pdpt = (struct page_table*)KADDR(PAGE_ADDR(*entry));
	struct page_info *page = page_alloc(BUDDY_4K_PAGE | ALLOC_ZERO);
	++page->pp_ref;
	struct page_table *clone_pdpt = page2kva(page);

	for(int i=0; i<PAGE_TABLE_ENTRIES; i++) {
		if(orig_pdpt->entries[i]) {
			struct page_info *pdir_page = copy_pdir(&orig_pdpt->entries[i]);
			clone_pdpt->entries[i] = PAGE_ADDR(page2pa(pdir_page)) | (orig_pdpt->entries[i] & PAGE_MASK);

			// cprintf("pdpt - i=%d, orig_entry=%p, clone_entry=%p, orig_flags=%p, clone_flags=%p\n", 
			// i, 
			// orig_pdpt->entries[i], 
			// clone_pdpt->entries[i],
			// orig_pdpt->entries[i] & PAGE_MASK,
			// clone_pdpt->entries[i] & PAGE_MASK);
		}
	}

	return page;
}

struct page_table *copy_pml4(struct page_table *orig_pml4) 
{
	struct page_info *page = page_alloc(BUDDY_4K_PAGE | ALLOC_ZERO);
	++page->pp_ref;
	struct page_table *clone_pml4 = page2kva(page);

	// deep copy entries recursively
	for(int i=0; i<PML4_INDEX(USER_LIM); i++) {
		if(orig_pml4->entries[i]) {
			struct page_info *pdpt_page = copy_pdpt(&orig_pml4->entries[i]);
			clone_pml4->entries[i] = PAGE_ADDR(page2pa(pdpt_page)) | (orig_pml4->entries[i] & PAGE_MASK);

			// cprintf("pml4 - i=%d, orig_entry=%p, clone_entry=%p, orig_flags=%p, clone_flags=%p\n", 
			// i, 
			// orig_pml4->entries[i], 
			// clone_pml4->entries[i],
			// orig_pml4->entries[i] & PAGE_MASK,
			// clone_pml4->entries[i] & PAGE_MASK);
		}
	}

	// copy kernel entries
	for(int i=PML4_INDEX(KERNEL_VMA); i<PAGE_TABLE_ENTRIES; i++) {
		clone_pml4->entries[i] = orig_pml4->entries[i];
	}

	return clone_pml4;
}

/* Allocates a task struct for the child process and copies the register state,
 * the VMAs and the page tables. Once the child task has been set up, it is
 * added to the run queue.
 */
struct task *task_clone(struct task *task)
{
	/* LAB 5: your code here. */
	struct task *clone = kmalloc(sizeof *task);
	if (!task) {
		return NULL;
	}

	// Set general stuff
	clone->task_type = task->task_type;
	clone->task_status = TASK_RUNNABLE;
	clone->task_runs = 0;
	// clone->task_cpunum - TODO: what to do?

	// Set pid and ppid
	/* Find a free PID for the task in the PID mapping and associate the
	 * task with that PID. */
	pid_t pid;
	for (pid = 1; pid < pid_max; ++pid) {
		if (!tasks[pid]) {
			tasks[pid] = task;
			clone->task_pid = pid;
			break;
		}
	}
	/* We are out of PIDs. */
	if (pid == pid_max) {
		kfree(task);
		return NULL;
	}
	clone->task_ppid = task->task_pid;


	// Copy frame/register state and set RAX=0 to signal this is child
	clone->task_frame = task->task_frame;
	clone->task_frame.rax = 0;

	// Copy page tables
	clone->task_pml4 = copy_pml4(task->task_pml4);

	// Copy VMAs
	list_init(&clone->task_mmap);
	rb_init(&clone->task_rb);

	struct list *node;
	struct vma *orig_vma, *clone_vma;
	list_foreach(&task->task_mmap, node) {
		orig_vma = container_of(node, struct vma, vm_mmap);
		clone_vma = kmalloc(sizeof(struct vma));
		
		list_init(&clone_vma->vm_mmap);
		rb_node_init(&clone_vma->vm_rb);

		int name_len = strlen(orig_vma->vm_name);
		clone_vma->vm_name = strcpy(kmalloc(name_len), orig_vma->vm_name);
		clone_vma->vm_name[name_len] = '\0';
		clone_vma->base_offset = orig_vma->base_offset;
		clone_vma->vm_base = orig_vma->vm_base;
		clone_vma->vm_end = orig_vma->vm_end;
		clone_vma->vm_src = orig_vma->vm_src;
		clone_vma->vm_len = orig_vma->vm_len;
		clone_vma->vm_flags = orig_vma->vm_flags;
		insert_vma(clone, clone_vma);
	}

	// Init lists
	list_init(&clone->task_children);
	list_init(&clone->task_child);
	list_init(&clone->task_zombies);

	// Add to the run queue
	list_init(&clone->task_node);
	list_push(&runq, &clone->task_node);

	// TODO: add child to parent's list
	// What is the difference between children and child?

	return clone;
}

pid_t sys_fork(void)
{
	/* LAB 5: your code here. */
	struct task *clone = task_clone(cur_task);
	if(clone == NULL) {
		panic("Could not clone task!");
	}
	return clone->task_pid;
}

