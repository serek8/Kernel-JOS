#include <error.h>
#include <string.h>
#include <paging.h>
#include <task.h>
#include <cpu.h>
#include <spinlock.h>
#include <atomic.h>

#include <kernel/acpi.h>
#include <kernel/monitor.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/vma/insert.h>
#include <kernel/vma.h>

extern uint64_t gsbase_in_msr;
extern char bootstack[];
extern int runq_len;

pid_t pid_max = 1 << 16;
struct task **tasks = (struct task **)PIDMAP_BASE;
volatile size_t nuser_tasks = 0;

#ifndef USE_BIG_KERNEL_LOCK
struct spinlock tasks_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "tasks_lock",
#endif
};
#endif

/* Looks up the respective task for a given PID.
 * If check_perm is non-zero, this function checks if the PID maps to the
 * current task or if the current task is the parent of the task that the PID
 * maps to.
 */
struct task *pid2task(pid_t pid, int check_perm)
{
	struct task *task;
	
	/* PID 0 is the current task. */
	if (pid == 0) {
		return cur_task;
	}

	/* Limit the PID. */
	if ((uint64_t)pid >= (uint64_t)pid_max) {
		return NULL;
	}

	/* Look up the task in the PID map. */
	task = tasks[pid];

	/* No such mapping found. */
	if (!task) {
		return NULL;
	}

	/* If we don't have to do a permission check, we can simply return the
	 * task.
	 */
	if (!check_perm) {
		return task;
	}

	/* Check if the task is the current task or if the current task is the
	 * parent. If not, then the current task has insufficient permissions.
	 */
	if (task != cur_task && task->task_ppid != cur_task->task_pid) {
		return NULL;
	}

	return task;
}

void task_init(void)
{
	/* Allocate an array of pointers at PIDMAP_BASE to be able to map PIDs
	 * to tasks.
	 */
	/* LAB 3: your code here. */
	// Mapping for PIDMAP_BASE
	for(int i = 0; i<pid_max*sizeof(struct task **); i+=PAGE_SIZE){
		struct page_info *page = page_alloc(ALLOC_ZERO);
		page_insert(kernel_pml4, page, (void*)PIDMAP_BASE+i, PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC);
	}

	spin_init(&tasks_lock, "tasks_lock");
}

/* Sets up the virtual address space for the task. */
static int task_setup_vas(struct task *task)
{
	struct page_info *page;

	/* Allocate a page for the page table. */
	page = page_alloc(ALLOC_ZERO);

	if (!page) {
		return -ENOMEM;
	}

	++page->pp_ref;

	/* Now set task->task_pml4 and initialize the page table.
	 * Can you use kernel_pml4 as a template?
	 */

	/* LAB 3: your code here. */
	task->task_pml4 = page2kva(page);

	// copy entries from kernel space of kernel_pml4 to kernel space of task_pml4
	for(int i=PML4_INDEX(KERNEL_VMA); i<PAGE_TABLE_ENTRIES; i++) {
		task->task_pml4->entries[i] = kernel_pml4->entries[i];
	}
	
	return 0;
}

/* Allocates and initializes a new task.
 * On success, the new task is returned.
 */
struct task *task_alloc(pid_t ppid)
{
	struct task *task;
	pid_t pid;

	/* Allocate a new task struct. */
	task = kmalloc(sizeof *task);

	if (!task) {
		return NULL;
	}

	/* Set up the virtual address space for the task. */
	if (task_setup_vas(task) < 0) {
		kfree(task);
		return NULL;
	}

	/* Find a free PID for the task in the PID mapping and associate the
	 * task with that PID.
	 */
	#ifndef USE_BIG_KERNEL_LOCK
	spin_lock(&tasks_lock);
	#endif
	for (pid = 1; pid < pid_max; ++pid) {
		if (!tasks[pid]) {
			tasks[pid] = task;
			task->task_pid = pid;
			break;
		}
	}
	#ifndef USE_BIG_KERNEL_LOCK
	spin_unlock(&tasks_lock);
	#endif

	/* We are out of PIDs. */
	if (pid == pid_max) {
		kfree(task);
		return NULL;
	}

	/* Set up the task. */
	task->task_ppid = ppid;
	task->task_type = TASK_TYPE_USER;
	task->task_status = TASK_RUNNABLE;
	task->task_cpunum = this_cpu->cpu_id;
	task->task_swapped_pages = 0;
	task->task_active_pages = 0;
	spin_init(&task->task_lock, "task_lock");
	spin_init(&task->swap_update_lock, "swap_update_lock");
	CPU_SET_ALL(task->cpu_mask);
	task->task_runs = 0;
	task->schedule_ts = 0;
#ifdef BONUS_LAB5
	memset(&task->fd_table, 0, sizeof task->fd_table);
#endif
	
	// Init lists
	list_init(&task->task_mmap);
	list_init(&task->task_node);
	rb_init(&task->task_rb);
	list_init(&task->task_children);
	list_init(&task->task_child);
	list_init(&task->task_zombies);
	list_init(&task->task_rmap_elems);

	memset(&task->task_frame, 0, sizeof task->task_frame);

	task->task_frame.ds = GDT_UDATA | 3;
	task->task_frame.ss = GDT_UDATA | 3;
	task->task_frame.rsp = USTACK_TOP;
	task->task_frame.cs = GDT_UCODE | 3;

	// set IF flag to enable hardware interrupts
	// TODO: fix timer issue
	task->task_frame.rflags |= FLAGS_IF;

	/* You will set task->task_frame.rip later. */

	cprintf("[PID %5u] New task with PID %u, CPU=%d\n",
	        cur_task ? cur_task->task_pid : 0, task->task_pid, this_cpu->cpu_id);

	return task;
}

struct task *task_kernel_alloc(pid_t ppid)
{
	struct task *task;
	pid_t pid;

	/* Allocate a new task struct. */
	task = kmalloc(sizeof *task);

	if (!task) {
		return NULL;
	}

	/* Set up the virtual address space for the task. */
	if (task_setup_vas(task) < 0) {
		kfree(task);
		return NULL;
	}

	/* Find a free PID for the task in the PID mapping and associate the
	 * task with that PID.
	 */
	#ifndef USE_BIG_KERNEL_LOCK
	spin_lock(&tasks_lock);
	#endif
	for (pid = 1000; pid < pid_max; ++pid) {
		if (!tasks[pid]) {
			tasks[pid] = task;
			task->task_pid = pid;
			break;
		}
	}
	#ifndef USE_BIG_KERNEL_LOCK
	spin_unlock(&tasks_lock);
	#endif

	/* We are out of PIDs. */
	if (pid == pid_max) {
		kfree(task);
		return NULL;
	}

	/* Set up the task. */
	task->task_ppid = ppid;
	task->task_type = TASK_TYPE_KERNEL;
	task->task_status = TASK_RUNNABLE;
	task->task_cpunum = this_cpu->cpu_id;
	CPU_SET_ALL(task->cpu_mask);
	task->task_runs = 0;
	task->schedule_ts = 0;
	
	// Init lists
	list_init(&task->task_mmap);
	list_init(&task->task_node);
	rb_init(&task->task_rb);
	list_init(&task->task_children);
	list_init(&task->task_child);
	list_init(&task->task_zombies);
	list_init(&task->task_rmap_elems);

	memset(&task->task_frame, 0, sizeof task->task_frame);

	task->task_frame.ds = GDT_KDATA | 0;
	task->task_frame.ss = GDT_KDATA | 0;
	task->task_frame.cs = GDT_KCODE | 0;

	// set IF flag to enable hardware interrupts
	// TODO: fix timer issue
	// task->task_frame.rflags |= FLAGS_IF;

	/* You will set task->task_frame.rip later. */
	cprintf("[PID %5u] New kernel task with PID %u\n",
	        cur_task ? cur_task->task_pid : 0, task->task_pid);

	return task;
}

void find_segment_names(char *buffer, int max_bytes, struct elf *elf_hdr, struct elf_proghdr hdr){
	for(int section_i=0; section_i<elf_hdr->e_shnum; section_i++){
			struct elf_secthdr *sect_hdr = (struct elf_secthdr *)(((uint64_t)elf_hdr) + elf_hdr->e_shoff + section_i*64);
			struct elf_secthdr *str_sect_hdr = (struct elf_secthdr *)(((uint64_t)elf_hdr) + elf_hdr->e_shoff + elf_hdr->e_shstrndx*64);
			char *str_sect = (char *)((uint8_t*)elf_hdr + str_sect_hdr->sh_offset);
			char *str = str_sect + sect_hdr->sh_name;
			if(sect_hdr->sh_addr >= hdr.p_va &&  sect_hdr->sh_addr < hdr.p_va + hdr.p_memsz){
				int saved_bytes = snprintf(buffer, max_bytes, "%s ", str);
				// cprintf("locl buffer=%s\n", buffer);
				buffer += saved_bytes;
				max_bytes -= saved_bytes;
			}
		}
}

void choose_segment_name(char *buffer, int max_bytes, struct elf *elf_hdr, struct elf_proghdr hdr){
	if(hdr.p_flags == ELF_PROG_FLAG_EXEC + ELF_PROG_FLAG_READ){
		snprintf(buffer, max_bytes, ".text");
	} else if(hdr.p_flags == ELF_PROG_FLAG_READ){
		snprintf(buffer, max_bytes, ".rodata");
	} else if(hdr.p_flags == ELF_PROG_FLAG_READ + ELF_PROG_FLAG_WRITE){
		snprintf(buffer, max_bytes, ".data");
	} else{
		panic("ELF FLAG NOT RECOGNISED");
	}

}

/* Sets up the initial program binary, stack and processor flags for a user
 * process.
 * This function is ONLY called during kernel initialization, before running
 * the first user-mode environment.
 *
 * This function loads all loadable segments from the ELF binary image into the
 * task's user memory, starting at the appropriate virtual addresses indicated
 * in the ELF program header.
 * At the same time it clears to zero any portions of these segments that are
 * marked in the program header as being mapped but not actually present in the
 * ELF file, i.e., the program's .bss section.
 *
 * All this is very similar to what our boot loader does, except the boot
 * loader also needs to read the code from disk. Take a look at boot/main.c to
 * get some ideas.
 *
 * Finally, this function maps one page for the program's initial stack.
 */
void task_load_elf(struct task *task, uint8_t *binary)
{
	/* Hints:
	 * - Load each program segment into virtual memory at the address
	 *   specified in the ELF section header.
	 * - You should only load segments with type ELF_PROG_LOAD.
	 * - Each segment's virtual address can be found in p_va and its
	 *   size in memory can be found in p_memsz.
	 * - The p_filesz bytes from the ELF binary, starting at binary +
	 *   p_offset, should be copied to virtual address p_va.
	 * - Any remaining memory bytes should be zero.
	 * - Use populate_region() and protect_region().
	 * - Check for malicious input.
	 *
	 * Loading the segments is much simpler if you can move data directly
	 * into the virtual addresses stored in the ELF binary.
	 * So in which address space should we be operating during this
	 * function?
	 *
	 * You must also do something with the entry point of the program, to
	 * make sure that the task starts executing there.
	 */

	/* LAB 3: your code here. */
	struct elf *elf_hdr = (struct elf *)binary;
	struct elf_proghdr *prog_hdr = (struct elf_proghdr *)((char *)elf_hdr + elf_hdr->e_phoff);
	char buffer[100];
	task->task_frame.rip = elf_hdr->e_entry;
	// cprintf("+ - - Program Headers - - +\n");
	for(uint64_t i = 0; i<elf_hdr->e_phnum; i++){
		struct elf_proghdr hdr = prog_hdr[i];
		if(!(hdr.p_type & ELF_PROG_LOAD)) {
			continue;
		}
		uint64_t flags = VM_READ;
		flags += (hdr.p_flags & (1<<(ELF_PROG_FLAG_EXEC-1))) ? VM_EXEC : 0;
		flags += (hdr.p_flags & (1<<(ELF_PROG_FLAG_WRITE-1))) ? VM_WRITE : 0;
		// cprintf("| [%d] vma_flags=0x%lx, elf_flags=0x%lx, elf_type=%x\n"
		// 	"|   va=%p, pa=%p, mem_size=%u file_size=%u\n", 
		// 	i, flags, hdr.p_flags, hdr.p_type, hdr.p_va, hdr.p_pa, hdr.p_memsz, hdr.p_filesz);
		
		
		if(hdr.p_va+hdr.p_memsz >= KERNEL_VMA){
			panic("The binary tries to overwrite KERNEL_VMA!\n");
		}
		// skip weird program headers
		if(hdr.p_va == 0x0 || hdr.p_memsz == 0) {
			continue;
		}
		choose_segment_name(buffer, 100, elf_hdr, hdr);
		// cprintf("|   sections=%s\n+ - - - - \n", buffer);
		
		
		if(hdr.p_filesz > 0){
			add_executable_vma(task, buffer, (void*)hdr.p_va, hdr.p_memsz, flags, (void*)(binary+hdr.p_offset), hdr.p_filesz);
		}
		else{
			add_anonymous_vma(task, buffer, (void*)hdr.p_va, hdr.p_memsz, flags);
		}
	}
	

	/* Now map one page for the program's initial stack at virtual address
	 * USTACK_TOP - PAGE_SIZE.
	 */

	/* LAB 3: your code here. */
	add_anonymous_vma(task, "stack", (void*)USTACK_TOP-PAGE_SIZE, PAGE_SIZE, VM_READ | VM_WRITE);
	task->task_frame.rsp = USTACK_TOP;

}

/* Allocates a new task with task_alloc(), loads the named ELF binary using
 * task_load_elf() and sets its task type.
 * If the task is a user task, increment the number of user tasks.
 * This function is ONLY called during kernel initialization, before running
 * the first user-mode task.
 * The new task's parent PID is set to 0.
 */
void task_create(uint8_t *binary, enum task_type type)
{
	/* LAB 3: your code here. */
	struct task *task = task_alloc(0);
	if(!task){
		panic("Could not create task!\n");
	}

	// TODO: load ELF binary
	load_pml4((void*)PADDR(task->task_pml4));
	task_load_elf(task, binary);

	task->task_type = type;
	atomic_inc(&nuser_tasks);
	
	/* LAB 5: your code here. */
	ADD_NEXTQ(task);
	cprintf("task_create: lrunq_len=%d\n", lrunq_len);
	// cprintf("# create/pushed task->task_pid=%d\n", task->task_pid);
	
}
void isr_kernel_task_stub(uint64_t kstack_top);
void ktask_base(void *kernel_task_entry){ 
	((void(*)())kernel_task_entry)();
	cur_task->task_status = TASK_SCHEDULE_KILL;
	ksched_yield();
}

// This function can be used only from a kernel thread
void ksched_yield(){
	isr_kernel_task_stub(this_cpu->cpu_tss.rsp[0]);
}

void task_kernel_create(void *entry_point)
{
	struct task *task = task_kernel_alloc(0);
	load_pml4((void*)PADDR(task->task_pml4));
	populate_region(task->task_pml4, (void*)USTACK_TOP-PAGE_SIZE, PAGE_SIZE, PAGE_PRESENT | PAGE_WRITE | PAGE_USER, NULL);
	task->task_frame.rsp = USTACK_TOP;
	task->task_frame.rdi = (uint64_t)entry_point;
	task->task_frame.rip = (uint64_t)ktask_base;
	ADD_NEXTQ(task);
	atomic_inc(&nuser_tasks);
}


/* Free the task and all of the memory that is used by it.
 */
void task_free(struct task *task)
{
	struct task *waiting;

	/* LAB 5: your code here. */
	/* If we are freeing the current task, switch to the kernel_pml4
	 * before freeing the page tables, just in case the page gets re-used.
	 */
	if (task == cur_task) {
		load_pml4((struct page_table *)PADDR(kernel_pml4));
	}
	rmap_free_task_rmap_elems(&task->task_rmap_elems);
	

	#ifndef USE_BIG_KERNEL_LOCK
	spin_lock(&tasks_lock);
	#endif
	/* Unmap the task from the PID map. */
	tasks[task->task_pid] = NULL;
	#ifndef USE_BIG_KERNEL_LOCK
	spin_unlock(&tasks_lock);
	#endif

	/* Unmap the user pages. */
	free_vmas(task);
	unmap_user_pages(task->task_pml4);

	/* Note the task's demise. */
	cprintf("[PID %5u] Freed task with PID %u\n", cur_task ? cur_task->task_pid : 0,
	    task->task_pid);

	if (task == cur_task) {
		cur_task = NULL;
	}

	/* Free the task. */
	kfree(task);
}

/* Frees the task. If the task is the currently running task, then this
 * function runs a new task (and does not return to the caller).
 */
void task_destroy(struct task *task)
{
	/* LAB 5: your code here. */
	int current = 0;
	if(task == cur_task) {
		current = 1;
	}

	LOCK_TASK(task);
	int ppid = task->task_ppid;


	if(!current){
		if(task->task_status != TASK_RUNNING){
			if(task->task_cpunum == TASK_CPUNUM_GLOBAL_RUNQ){
				atomic_dec(&runq_len);
			}
			else{
				atomic_dec(&cpus[task->task_cpunum].runq_len);
			}
		}
	}

	task->task_status = TASK_DYING;
	
	// check if child process -> becomes zombie if parent is still running
	if(ppid != 0) {
		struct task *parent = pid2task(task->task_ppid, 0);

		// Chicken - egg problem when locking parent task that might get deleted at the same time
		// if it gets deleted at the same time, this child becomes a root task and not a zombie
		// therefore it needs to delete itself
		if(!TRY_LOCK_TASK(parent)) {
			while(tasks[ppid] != NULL && !TRY_LOCK_TASK(parent));
			if(tasks[ppid] == NULL) {
				UNLOCK_TASK(task);
				task_destroy(task);
				return;
			}
		}
		// cprintf("[PID %5u] Gets a zombie, ppid=%d, CPU=%d\n", task->task_pid, task->task_ppid, this_cpu->cpu_id);
		// add to zombies list of parent
		list_remove(&task->task_node); // remove from local runq
		
		list_push(&parent->task_zombies, &task->task_node);
		// remove from children list
		list_remove(&task->task_child);
		
		// notify parent if waiting and not scheduled
		if(parent && parent->task_status == TASK_NOT_RUNNABLE) {
			parent->task_frame.rax = task->task_pid; // set proper return value for wait syscall
			parent->task_status = TASK_RUNNABLE;
			ADD_NEXTQ(parent);
			task_remove_child(task);
		}
		UNLOCK_TASK(parent);
	} else {
		// a parent task is exiting
		cprintf("[PID %5u] Exiting gracefully, CPU=%d\n", task->task_pid, this_cpu->cpu_id);
		
		// remove all zombies
		struct list *node = NULL, *next = NULL;
		list_foreach_safe(&task->task_zombies, node, next) {
			struct task *zombie = container_of(node, struct task, task_node);
			cprintf("[PID %5u] Reaping task with PID %d\n", cur_task->task_pid, zombie->task_pid);
			task_remove_child(zombie);
		}

		// detach children from the parent list, change their parent to PID #0
		list_foreach_safe(&task->task_children, node, next) {
			struct task *child = container_of(node, struct task, task_child);
			list_remove(&child->task_child);
			child->task_ppid = 0;
		}

		// remove task
		list_remove(&task->task_node); // remove from local runq
		task_free(task);
	}
	
	atomic_dec(&nuser_tasks);

	if(current) {
		sched_yield();
	}
}

void task_remove_child(struct task *task) 
{
	if(task->task_status == TASK_DYING){ // if child is also dying
		struct list *node = NULL, *next = NULL;
		list_foreach_safe(&task->task_children, node, next) {
			struct task *child = container_of(node, struct task, task_child);
			list_remove(&child->task_child);
			child->task_ppid = 0;
			task_remove_child(child);
		}
		node = NULL;
		next = NULL;
		list_foreach_safe(&task->task_zombies, node, next) {
			struct task *zombie = container_of(node, struct task, task_node);
			task_remove_child(zombie);
		}
		list_remove(&task->task_node);
		list_remove(&task->task_child);
		task_free(task);
	}

	// TODO: check if there are still running children -> make to orphans?
}

/*
 * Restores the register values in the trap frame with the iretq or sysretq
 * instruction. This exits the kernel and starts executing the code of some
 * task.
 *
 * This function does not return.
 */
void task_pop_frame(struct int_frame *frame)
{
	// cprintf(">> Will enter user mode\n");
	// cprintf("CPU %d, runq_len=%d\n", this_cpu->cpu_id, lrunq_len);
	#ifdef BONUS_LAB3
	// BONUS_LAB3: flush CPU buffers before switching to user process
	MDS_buff_overwrite();
	#endif
	switch (frame->int_no) {
#ifdef LAB3_SYSCALL
	case 0x80: 
	if(this_cpu->gsbase_in_msr == 1){
		asm volatile("swapgs"); // gsbase_in_msr = 0;
	}
	this_cpu->gsbase_in_msr = 1;
	sysret64(frame); break;
#endif
	default: 
		if(this_cpu->gsbase_in_msr == 0){
			asm volatile("swapgs");
			this_cpu->gsbase_in_msr = 1;
		}
		lapic_eoi();
		iret64(frame); 
		break;
	}

	panic("We should have gone back to userspace!");
}

/* Context switch from the current task to the provided task.
 * Note: if this is the first call to task_run(), cur_task is NULL.
 *
 * This function does not return.
 */
void task_run(struct task *task)
{
	/*
	 * Step 1: If this is a context switch (a new task is running):
	 *     1. Set the current task (if any) back to
	 *        TASK_RUNNABLE if it is TASK_RUNNING (think about
	 *        what other states it can be in),
	 *     2. Set 'cur_task' to the new task,
	 *     3. Set its status to TASK_RUNNING,
	 *     4. Update its 'task_runs' counter,
	 *     5. Use load_pml4() to switch to its address space.
	 * Step 2: Use task_pop_frame() to restore the task's
	 *     registers and drop into user mode in the
	 *     task.
	 *
	 * Hint: This function loads the new task's state from
	 *  e->task_frame.  Go back through the code you wrote above
	 *  and make sure you have set the relevant parts of
	 *  e->task_frame to sensible values.
	 */

	/* LAB 3: Your code here. */
	if(cur_task == NULL){
		cur_task = task;
	}
	
	if(cur_task->task_status == TASK_RUNNING){
		cur_task->task_status = TASK_RUNNABLE;
	}
	
	cur_task = task;
	// task got killed from a different processor
	if(cur_task->task_status == TASK_DYING){
		cur_task = NULL;
		sched_yield();
	}

	// This lock prevents swapper from updating this task's PTEs
	while(!TRY_LOCK_TASK_SWAPPER(task)) cprintf("PID %d is waiting task_run\n", task->task_pid);

	task->task_status = TASK_RUNNING;
	task->task_runs += 1;
	// It also flushes TLB. So all the swapper modifications are updated.
	load_pml4((void*)PADDR(task->task_pml4));
	#ifdef USE_BIG_KERNEL_LOCK
	// cprintf("task_pop_frame, task_type=%d\n", cur_task->task_type);
	spin_unlock(&kernel_lock);
	#endif
	

	task_pop_frame(&task->task_frame);
	
}
