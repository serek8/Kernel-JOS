#include <types.h>
#include <cpu.h>
#include <list.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/paging.h>

#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>

#define SCHEDULE_TIME_BLOCK 1000*1000*1000
#define SCHEDULE_TIME_EXPIRED (uint64_t)-1

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
	list_init(&lrunq);
	list_init(&lnextq);
	lrunq_len = 0;
}

void sched_init_mp(void)
{
	/* LAB 6: your code here. */
	list_init(&lrunq);
	list_init(&lnextq);
	lrunq_len = 0;
}

/* Runs the next runnable task. */
void sched_yield(void)
{
	/* LAB 5: your code here. */
	if(cur_task != NULL && (cur_task->task_status == TASK_RUNNABLE || cur_task->task_status == TASK_RUNNING)){ 
		if(cur_task->schedule_ts != SCHEDULE_TIME_EXPIRED && read_tsc() - cur_task->schedule_ts < SCHEDULE_TIME_BLOCK){
			task_run(cur_task);
		} else{ // allocated time for a task expires
			list_push_left(&lrunq, &cur_task->task_node);
		}
	}
	
	if(list_is_empty(&lrunq)){
		cprintf("Destroyed the only task - nothing more to do!\n");
		sched_halt();
	}

	struct task *next_task = container_of(list_pop_left(&lrunq), struct task, task_node);
	next_task->schedule_ts = read_tsc();
	task_run(next_task);
}

void sched_set_expired(void){
	cur_task->schedule_ts = SCHEDULE_TIME_EXPIRED;
}

/* For now jump into the kernel monitor. */
void sched_halt()
{
	#ifdef USE_BIG_KERNEL_LOCK
	cprintf("CPU #%d halted.\n", this_cpu->cpu_id);
	spin_unlock(&kernel_lock);
	asm volatile(
		"cli\n"
		"hlt\n");
	#endif

	while(1){
		monitor(NULL);
	}	
}

