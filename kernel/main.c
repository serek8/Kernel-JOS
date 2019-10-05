#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/mp.h>
#include <kernel/pic.h>
#include <kernel/sched.h>
#include <kernel/tests.h>

#include <boot.h>
#include <stdio.h>
#include <string.h>
#include <kernel/sched/task.h>
#include <kernel/sched/gdt.h>
#include <kernel/sched/idt.h>
#include <kernel/sched/syscall.h>
#include <spinlock.h>

extern struct page_table *kernel_pml4;
#ifdef BONUS_LAB5
struct page_info *zero_dedup;
#endif

void kernel_task_entry(){
	cprintf("Hello in kernel task\n");
	return;
}
void kmain(struct boot_info *boot_info)
{
	extern char edata[], end[];
	struct rsdp *rsdp;

	/* Before doing anything else, complete the ELF loading process.
	 * Clear the uninitialized global data (BSS) section of our program.
	 * This ensures that all static/global variables start out zero.
	 */
	memset(edata, 0, end - edata);

	/* Initialize the console.
	 * Can't call cprintf until after we do this! */
	cons_init();
	cprintf("\n");

	/* Set up segmentation, interrupts and system calls. */
	gdt_init();
	idt_init();
	syscall_init();

	/* Lab 1 memory management initialization functions */
	mem_init(boot_info);

	/* Set up the slab allocator. */
	kmem_init();

	/* Set up the interrupt controller and timers */
	pic_init();
	rsdp = rsdp_find();
	madt_init(rsdp);
	lapic_init();
	hpet_init(rsdp);

	/* Set up the tasks. */
	task_init();
	sched_init();

	lab3_check_populate_protect(kernel_pml4);
	
	#ifdef BONUS_LAB5
	// Set up zero-page for dedup
	zero_dedup = page_alloc(BUDDY_4K_PAGE | ALLOC_ZERO);
	#endif

	#ifdef USE_BIG_KERNEL_LOCK
	spin_init(&kernel_lock, "kernel_lock");
	spin_lock(&kernel_lock);
	#endif

	mem_init_mp();
	cprintf("will run boot_cpus\n");
	boot_cpus();

	
	// TASK_CREATE(user_evilchild, TASK_TYPE_USER);
	// TASK_CREATE(user_yield, TASK_TYPE_USER);
	// TASK_CREATE(user_yield, TASK_TYPE_USER);
	// TASK_CREATE(user_yield, TASK_TYPE_USER);
	// TASK_CREATE(user_yield, TASK_TYPE_USER);
	task_kernel_create(kernel_task_entry);
	sched_yield();
	// panic("---- END\n");


#if defined(TEST)
	TASK_CREATE(TEST, TASK_TYPE_USER);
	sched_yield();
#else
	lab3_check_kmem();

	/* Drop into the kernel monitor. */
	while (1)
		monitor(NULL);
#endif
}

/*
 * Variable panicstr contains argument to first call to panic; used as flag
 * to indicate that the kernel has already called panic.
 */
const char *panicstr;

/*
 * Panic is called on unresolvable fatal errors.
 * It prints "panic: mesg", and then enters the kernel monitor.
 */
void _panic(const char *file, int line, const char *fmt,...)
{
	va_list ap;

	if (panicstr)
		goto dead;
	panicstr = fmt;

	/* Be extra sure that the machine is in as reasonable state */
	__asm __volatile("cli; cld");

	va_start(ap, fmt);
	cprintf("kernel panic at %s:%d: ", file, line);
	vcprintf(fmt, ap);
	cprintf("\n");
	va_end(ap);

dead:
	/* Break into the kernel monitor */
	while (1)
		monitor(NULL);
}

/* Like panic, but don't. */
void _warn(const char *file, int line, const char *fmt,...)
{
	va_list ap;

	va_start(ap, fmt);
	cprintf("kernel warning at %s:%d: ", file, line);
	vcprintf(fmt, ap);
	cprintf("\n");
	va_end(ap);
}

