#include <error.h>
#include <string.h>
#include <assert.h>

#include <x86-64/asm.h>
#include <x86-64/gdt.h>

#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/sched.h>

extern void syscall64(void);

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

	task = pid2task(pid, 1);

	if (!task) {
		return -1;
	}

	cprintf("[PID %5u] Exiting gracefully\n");
	task_destroy(task);

	return 0;
}

/* Dispatches to the correct kernel function, passing the arguments. */
int64_t syscall(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3,
        uint64_t a4, uint64_t a5, uint64_t a6)
{
	/*
	 * Call the function corresponding to the 'syscallno' parameter.
	 * Return any appropriate return value.
	 */
	/* LAB 3: your code here. */
	// cprintf("syscallno=%d, a1=%s\n", syscallno, a1);

	switch (syscallno) {
		case SYS_cputs:
			sys_cputs((const char*)a1, a2);
			return 0;
		case SYS_cgetc:
			return sys_cgetc();
		case SYS_getpid:
			return sys_getpid();
		case SYS_kill:
			return sys_kill(a2);
			
	default:
		cprintf("Kernel doesn not support system call=%d\n", syscallno);
		return -ENOSYS;
	}
}

void syscall_handler(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6)
{
	struct int_frame *frame;

	/* Syscall from user mode. */
	assert(cur_task);

	/* Avoid using the frame on the stack. */
	frame = &cur_task->task_frame;

	/* Issue the syscall. */
	frame->rax = syscall(syscallno, a1, a2, a3, a4, a5, a6);

	/* Return to the current task, which should be running. */
	task_run(cur_task);
}

