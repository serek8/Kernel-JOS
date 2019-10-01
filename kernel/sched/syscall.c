#include <error.h>
#include <string.h>
#include <assert.h>

#include <x86-64/asm.h>
#include <x86-64/gdt.h>

#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

extern void syscall64(void);

uint64_t gsbase_in_msr = 0; // if '1' then MSR register has value of %gs base, leaving %gs empty. If '0', base is loaded to %gs.

void syscall_init(void)
{
	/* LAB 3: your code here. */
	// set segment selector to use for kernel and user when calling syscall
	cprintf("syscall_init syscall_init syscall_init \n");


	union star_reg reg = {
		.kern_sel = GDT_KCODE,
		.user_sel = GDT_KDATA | 3,
	};

	write_msr(MSR_STAR, reg.reg);

	write_msr(MSR_LSTAR, (uint64_t)syscall64);
	write_msr(MSR_SFMASK, FLAGS_IF);
	
	write_msr(MSR_EFER, read_msr(MSR_EFER) | MSR_EFER_SCE);
	cprintf("read_msr(MSR_EFER)=%p\n", read_msr(MSR_EFER));



	write_msr(MSR_KERNEL_GS_BASE, (uint64_t)this_cpu);
	gsbase_in_msr = 1;
	
}

/*
 * Print a string to the system console.
 * The string is exactly 'len' characters long.
 * Destroys the environment on memory errors.
 */
static void sys_cputs(const char *s, size_t len)
{
	/* Check that the user has permission to read memory [s, s+len).
	 * Destroy the environment if not. */
	/* LAB 3: your code here. */
	assert_user_mem(cur_task, (void*)s, len, PAGE_PRESENT | PAGE_USER);

	/* Print the string supplied by the user. */
	cprintf("%.*s", len, s);
}

/*
 * Read a character from the system console without blocking.
 * Returns the character, or 0 if there is no input waiting.
 */
static int sys_cgetc(void)
{
	return cons_getc();
}

/* Returns the PID of the current task. */
static pid_t sys_getpid(void)
{
	return cur_task->task_pid;
}

static int sys_kill(pid_t pid)
{
	struct task *task;

	/* LAB 5: your code here. */

	task = pid2task(pid, 1);

	if (!task) {
		return -1;
	}

	task_destroy(task);

	return 0;
}

#ifdef BONUS_LAB5
static uint8_t *get_binary_mapping(char *binary)
{
	RETURN_TASK_BINARY(binary, badsegment);
	RETURN_TASK_BINARY(binary, basicfork);
	RETURN_TASK_BINARY(binary, breakpoint);
	RETURN_TASK_BINARY(binary, cowfork);
	RETURN_TASK_BINARY(binary, divzero);
	RETURN_TASK_BINARY(binary, dontneed);
	RETURN_TASK_BINARY(binary, evilchild);
	RETURN_TASK_BINARY(binary, evilhello);
	RETURN_TASK_BINARY(binary, evilmadvise);
	RETURN_TASK_BINARY(binary, evilmmap);
	RETURN_TASK_BINARY(binary, evilmprotect);
	RETURN_TASK_BINARY(binary, evilmunmap);
	RETURN_TASK_BINARY(binary, faultexec);
	RETURN_TASK_BINARY(binary, faultwrite);
	RETURN_TASK_BINARY(binary, hello);
	RETURN_TASK_BINARY(binary, kernelexec);
	RETURN_TASK_BINARY(binary, kernelread);
	RETURN_TASK_BINARY(binary, kernelwrite);
	RETURN_TASK_BINARY(binary, lazyvma);
	RETURN_TASK_BINARY(binary, mapexec);
	RETURN_TASK_BINARY(binary, mapfixed);
	RETURN_TASK_BINARY(binary, mapleft);
	RETURN_TASK_BINARY(binary, mapnone);
	RETURN_TASK_BINARY(binary, mapnull);
	RETURN_TASK_BINARY(binary, mapright);
	RETURN_TASK_BINARY(binary, mapwrite);
	RETURN_TASK_BINARY(binary, mergevma);
	RETURN_TASK_BINARY(binary, mmap);
	RETURN_TASK_BINARY(binary, mprotect);
	RETURN_TASK_BINARY(binary, munmap);
	RETURN_TASK_BINARY(binary, mustneed);
	RETURN_TASK_BINARY(binary, nullexec);
	RETURN_TASK_BINARY(binary, nullhello);
	RETURN_TASK_BINARY(binary, nullread);
	RETURN_TASK_BINARY(binary, nullwrite);
	RETURN_TASK_BINARY(binary, overflowhello);
	RETURN_TASK_BINARY(binary, persistnone);
	RETURN_TASK_BINARY(binary, protexec);
	RETURN_TASK_BINARY(binary, protnone);
	RETURN_TASK_BINARY(binary, protwrite);
	RETURN_TASK_BINARY(binary, reaper);
	RETURN_TASK_BINARY(binary, softint);
	RETURN_TASK_BINARY(binary, splitvma);
	RETURN_TASK_BINARY(binary, testbss);
	RETURN_TASK_BINARY(binary, thp);
	RETURN_TASK_BINARY(binary, unmapleft);
	RETURN_TASK_BINARY(binary, unmapright);
	RETURN_TASK_BINARY(binary, unmaptext);
	RETURN_TASK_BINARY(binary, vma);
	RETURN_TASK_BINARY(binary, wait);
	RETURN_TASK_BINARY(binary, waitnone);
	RETURN_TASK_BINARY(binary, waitself);
	RETURN_TASK_BINARY(binary, willneed);
	RETURN_TASK_BINARY(binary, yield);

	return NULL;
}

static int sys_exec(char *binary)
{
	uint8_t *bin = get_binary_mapping(binary);
	if(bin == NULL) {
		return -1;
	}
	struct task *task = cur_task;

	// delete all existing user mappings
	remove_vma_range(task, (void*)0x0, USER_LIM);

	list_init(&task->task_mmap);
	list_init(&task->task_node);
	rb_init(&task->task_rb);

	// reset int frame
	memset(&task->task_frame, 0, sizeof task->task_frame);

	task->task_frame.ds = GDT_UDATA | 3;
	task->task_frame.ss = GDT_UDATA | 3;
	task->task_frame.rsp = USTACK_TOP;
	task->task_frame.cs = GDT_UCODE | 3;

	// set IF flag to enable hardware interrupts
	task->task_frame.rflags |= FLAGS_IF;

	// map new process in
	task_load_elf(task, bin);

	sched_yield();

	return 0;
}
#endif

/* Dispatches to the correct kernel function, passing the arguments. */
int64_t syscall(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3,
        uint64_t a4, uint64_t a5, uint64_t a6)
{
	/*
	 * Call the function corresponding to the 'syscallno' parameter.
	 * Return any appropriate return value.
	 */
	/* LAB 3: your code here. */
	switch (syscallno) {
		case SYS_cputs:
			sys_cputs((const char*)a1, a2);
			return 0;
		case SYS_cgetc:
			return sys_cgetc();
		case SYS_getpid:
			return sys_getpid();
		case SYS_kill:
			cprintf("SYS_kill a1=%d, a2=%d\n", a1, a2);
			return sys_kill(a1);
		case SYS_mquery:
			return sys_mquery((struct vma_info*)a1, (void*)a2);
		case SYS_mmap:
			return (uintptr_t)sys_mmap((void*)a1, a2, a3, a4, a5, a6);
		case SYS_munmap:
			sys_munmap((void*)a1, a2);
			return 0;
		case SYS_mprotect:
			return sys_mprotect((void*)a1, a2, (int)a3);
		case SYS_madvise:
			return sys_madvise((void*)a1, a2, (int) a3);
		case SYS_yield:
			sched_set_expired();
			sched_yield();
			return 0;
		case SYS_fork:
			return sys_fork();
		case SYS_wait:
			return sys_wait((int *)a1);
		case SYS_waitpid:
			return sys_waitpid(a1, (int *)a2, a3);
		#ifdef BONUS_LAB5
		case SYS_exec:
			return sys_exec((char*)a1);
		#endif
			
	default:
		cprintf("Kernel does not support system call=%d\n", syscallno);
		return -ENOSYS;
	}
}

void syscall_handler(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6)
{
	struct int_frame *frame;

	gsbase_in_msr = 0;
	/* Syscall from user mode. */
	assert(cur_task);

	/* Avoid using the frame on the stack. */
	frame = &cur_task->task_frame;

	/* Issue the syscall. */
	frame->rax = syscall(syscallno, a1, a2, a3, a4, a5, a6);

	/* Return to the current task, which should be running. */
	task_run(cur_task);
}

