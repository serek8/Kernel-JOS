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
#ifdef DEBUG_SPINLOCK
	.name = "runq_lock",
#endif
};
#endif

extern volatile size_t nuser_tasks;

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
			ADD_NEXTQ(cur_task);
		}
	}
	
	while(list_is_empty(&lrunq)){
		// halt execution if there are no user tasks anymore
		if(nuser_tasks == 0) {
			sched_halt();
		}

		// try to get lock for global runq -> if successful migrate tasks
		if(spin_trylock(&runq_lock)) {
			// cprintf("cpu=%d, nuser_tasks=%d, lrunq_len=%d\n", this_cpu->cpu_id, nuser_tasks, lrunq_len);
			
			int task_share = ROUNDUP(nuser_tasks, ncpus) / ncpus;
			// take tasks from global runq
			if(task_share > lrunq_len) {
				// cprintf("+++ take tasks %d, cpu=%d, \n", task_share-lrunq_len, this_cpu->cpu_id);
				for(int i=0; i<task_share-lrunq_len; i++) {
					// make sure that runq actually has that many tasks
					// there still could be many tasks at another CPU and less on the global runq
					if(!list_is_empty(&runq)) {
						struct task *task = container_of(list_pop_left(&runq), struct task, task_node);
						// cprintf("cpu=%d, task->pid=%d,\n", this_cpu->cpu_id, task->task_pid);
						LOCK_TASK(task);
						ADD_NEXTQ(task);
						UNLOCK_TASK(task);
					}
				}
			} else if(task_share < lrunq_len) {
				// put tasks from local runq to global runq
				// cprintf("+++ give tasks %d, cpu=%d, \n", lrunq_len-task_share, this_cpu->cpu_id);
				for(int i=0; i<lrunq_len-task_share; i++) {
					struct task *task = container_of(list_pop_left(&lnextq), struct task, task_node);
					LOCK_TASK(task);
					list_push_left(&runq, &task->task_node);
					UNLOCK_TASK(task);
				}
			}

			spin_unlock(&runq_lock);
		}

		if(!list_is_empty(&lnextq)) {
			// swap lrunq and lnextq
			struct list *head_nextq = list_head(&lnextq);
			list_remove(&lnextq);
			list_push_left(head_nextq, &lrunq);
			lrunq_len = 0;
		}
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

	this_cpu->cpu_status = CPU_HALTED;

	int last = 1;
	for(struct cpuinfo *cpu = cpus; cpu < cpus + ncpus; ++cpu) {
		if(cpu->cpu_status != CPU_HALTED) {
			last = 0;
			break;
		}
	}

	if(last) {
		cprintf("Destroyed the only task - nothing more to do!\n");
		while(1){
			monitor(NULL);
		}
	}

	// halt CPU
	asm volatile(
		"cli\n"
		"hlt\n");
}
