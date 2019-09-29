#include <types.h>
#include <cpu.h>
#include <list.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/paging.h>

#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>

struct list runq;

#ifndef USE_BIG_KERNEL_LOCK
struct spinlock runq_lock = {
#ifdef DBEUG_SPINLOCK
	.name = "runq_lock",
#endif
};
#endif

extern size_t nuser_tasks;

void sched_init(void)
{
	list_init(&runq);
}

void sched_init_mp(void)
{
	/* LAB 6: your code here. */
}

/* Runs the next runnable task. */
void sched_yield(void)
{
	/* LAB 5: your code here. */
	if(cur_task != NULL && (cur_task->task_status == TASK_RUNNABLE || cur_task->task_status == TASK_RUNNING)){ // check if the task is already in a queue. Otherwiese, we would push the task to the list even during normal syscalls.
		list_push_left(&runq, &cur_task->task_node);
		// cprintf("# pushed cur_task->task_pid=%d\n", cur_task->task_pid);
	}

	if(list_is_empty(&runq)){
		cprintf("Destroyed the only task - nothing more to do!\n");
		sched_halt();
	}
		

	struct task *next_task = container_of(list_pop_left(&runq), struct task, task_node);
	// cprintf("# popped next_task->task_pid=%d\n", next_task->task_pid);
	task_run(next_task);
}

/* For now jump into the kernel monitor. */
void sched_halt()
{
	while (1) {
		monitor(NULL);
	}
}

