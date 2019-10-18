#include <types.h>
#include <cpu.h>
#include <list.h>
#include <stdio.h>
#include <atomic.h>

#include <x86-64/asm.h>
#include <x86-64/paging.h>

#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>

#define SCHEDULE_TIME_BLOCK 1*1000*1000*1000
#define SCHEDULE_TIME_EXPIRED (uint64_t)-1

struct list runq;
volatile int runq_len = 0;

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
	sched_i = 0;
	lrunq_len = 0;
	spin_init(&runq_lock, "runq_lock");
}

void sched_init_mp(void)
{
	/* LAB 6: your code here. */
	list_init(&lrunq);
	list_init(&lnextq);
	sched_i = 0;
	lrunq_len = 0;
}

int is_affiliated_to_this_cpu(struct task *task){
	return ((task->cpu_mask.bits & (1 << this_cpu->cpu_id)));
}

void sched_yield_run_task();
/* Runs the next runnable task. */
void sched_yield(void)
{
	/* LAB 5: your code here. */
	if(cur_task != NULL && cur_task->task_status == TASK_SCHEDULE_KILL){
		task_destroy(cur_task);
	} else 	if(cur_task != NULL && (cur_task->task_status == TASK_RUNNABLE || cur_task->task_status == TASK_RUNNING)){ 
		if(cur_task->schedule_ts != SCHEDULE_TIME_EXPIRED && read_tsc() - cur_task->schedule_ts < SCHEDULE_TIME_BLOCK){
			sched_yield_run_task(cur_task);
		} else{ // allocated time for a task expires
			ADD_NEXTQ(cur_task);
		}
	}

	sched_i++;
	if(sched_i == 5) {
		sched_i = 0;
		int task_share = ROUNDUP(nuser_tasks, ncpus) / ncpus;
		
		if(task_share < lrunq_len) {
			// put tasks from local runq to global runq
			if(spin_trylock(&runq_lock)) {
				// cprintf("+++ give tasks %d, cpu=%d, \n", lrunq_len-task_share, this_cpu->cpu_id);
				// cprintf("Tasks exported periodicaly, currently=%d to_migrate=%d, cpu=%d\n", lrunq_len, lrunq_len-task_share, this_cpu->cpu_id);
				int tasks_to_migrate = lrunq_len-task_share;
				for(int i=0; i<tasks_to_migrate; i++) {
					struct task *task = NULL;
					if(!list_is_empty(&lnextq)) {
						task = container_of(list_pop(&lnextq), struct task, task_node);
					} else if(!list_is_empty(&lrunq)) {
						task = container_of(list_pop(&lrunq), struct task, task_node);
					}else{
						panic("no more tasks to migrate");
					}
					atomic_dec(&lrunq_len);
					atomic_inc(&runq_len);
					LOCK_TASK(task);
					task->task_cpunum = TASK_CPUNUM_GLOBAL_RUNQ;
					list_push_left(&runq, &task->task_node);
					UNLOCK_TASK(task);
				}
				// cprintf("task_share=%d, nuser_tasks=%d, runq_len=%d [0]=%d, [1]=%d, [2]=%d, [3]=%d, cpuid=%d\n", task_share, nuser_tasks, runq_len, cpus[0].runq_len, cpus[1].runq_len, cpus[2].runq_len, cpus[3].runq_len, this_cpu->cpu_id);
				spin_unlock(&runq_lock);
			}
		}
	}

	while(list_is_empty(&lrunq)){
		// halt execution if there are no user tasks anymore
		if(nuser_tasks == 0) {
			sched_halt();
		}
		// calculate how many tasks this CPU should have
		
		int task_share = ROUNDUP(nuser_tasks, ncpus) / ncpus;
		// take tasks from global runq
		if(task_share > lrunq_len) {
			if(lrunq_len == 0) {
				// CPU doesn't have any task
				// busy wait until there is a task on the runq and only then try to get the lock for it
				while(!runq_len && nuser_tasks);
			}
			if(spin_trylock(&runq_lock)) {
				// cprintf("+++ take tasks %d, cpu=%d, lrunq_len=%d, task_share=%d, nuser_tasks=%d\n", task_share-lrunq_len, this_cpu->cpu_id, lrunq_len, task_share, nuser_tasks);
				int tasks_to_take = task_share-lrunq_len;
				for(int i=0; i<tasks_to_take; i++) {
					// make sure that runq actually has that many tasks
					// there still could be many tasks at another CPU and less on the global runq
					if(!list_is_empty(&runq)) {
						struct task *task = container_of(list_pop_left(&runq), struct task, task_node);
						if(!is_affiliated_to_this_cpu(task)){
							list_push_left(&runq, &task->task_node); // it's a bit unfair but intuitive
							// cprintf("refused to local queue cpu=%d, task->pid=%d,\n", this_cpu->cpu_id, task->task_pid);
							continue;
						}
						atomic_dec(&runq_len);
						// cprintf("add to local queue cpu=%d, task->pid=%d,\n", this_cpu->cpu_id, task->task_pid);
						LOCK_TASK(task);
						task->task_cpunum = this_cpu->cpu_id;
						ADD_NEXTQ(task);
						UNLOCK_TASK(task);
					}
					else{
						// cprintf("was empty\n");
						break;
					}
				}
				spin_unlock(&runq_lock);
			} 
		} else if(task_share < lrunq_len) {
			// put tasks from local runq to global runq
			if(spin_trylock(&runq_lock)) {
				// cprintf("+++ give tasks %d, cpu=%d, \n", lrunq_len-task_share, this_cpu->cpu_id);
				// cprintf("Tasks exported old, currently=%d to_migrate=%d, pid=%d\n", lrunq_len, lrunq_len-task_share, task->task_pid);
				int tasks_to_migrate = lrunq_len-task_share;
				for(int i=0; i<tasks_to_migrate; i++) {
					struct task *task = NULL;
					if(!list_is_empty(&lnextq)) {
						task = container_of(list_pop(&lnextq), struct task, task_node);
					} else if(!list_is_empty(&lrunq)) {
						task = container_of(list_pop(&lrunq), struct task, task_node);
					}else{
						panic("no more tasks to migrate");
					}
					atomic_dec(&lrunq_len);
					atomic_inc(&runq_len);
					LOCK_TASK(task);
					task->task_cpunum = TASK_CPUNUM_GLOBAL_RUNQ;
					list_push_left(&runq, &task->task_node);
					UNLOCK_TASK(task);
				}
				spin_unlock(&runq_lock);
			}
		}
		
		if(list_is_empty(&lrunq) && !list_is_empty(&lnextq)) {
			// swap lrunq and lnextq
			struct list *head_nextq = list_head(&lnextq);
			list_remove(&lnextq);
			list_push_left(head_nextq, &lrunq);
		}
	}

	struct task *next_task = container_of(list_pop_left(&lrunq), struct task, task_node);
	atomic_dec(&lrunq_len);
	next_task->schedule_ts = read_tsc();
	sched_yield_run_task(next_task);
}



void sched_yield_run_task(struct task *next_task){
	int should_migrate = !is_affiliated_to_this_cpu(next_task);
	if(should_migrate && spin_trylock(&runq_lock)){ // task wants to migrate
	// cprintf("cpu=%d, cpu_mask=0x%x, will migrate=%d\n",this_cpu->cpu_id, next_task->cpu_mask.bits, (!(next_task->cpu_mask.bits & (1 << this_cpu->cpu_id))));
		LOCK_TASK(next_task);
		next_task->task_cpunum = TASK_CPUNUM_GLOBAL_RUNQ;
		list_push_left(&runq, &next_task->task_node);
		atomic_inc(&runq_len);
		UNLOCK_TASK(next_task);
		spin_unlock(&runq_lock);
		cur_task = NULL;
		sched_yield();
	}
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
		cprintf("Destroyed the only task - nothing more to do!, CPU=%d\n", this_cpu->cpu_id);
		while(1){
			monitor(NULL);
		}
	}

	// halt CPU
	asm volatile(
		"cli\n"
		"hlt\n");
}
int sys_sched_setaffinity(pid_t pid, unsigned cpusetsize, cpu_set_t *mask){
	if(pid == 0){
		pid = cur_task->task_pid;
	}
	int perm_check = 1;
	if(cur_task == NULL) {
		perm_check = 0;
	} else{
		perm_check = cur_task->task_type == TASK_TYPE_USER;
	}
	struct task *task = pid2task(pid, perm_check);
	if (task == NULL){
		return -1;
	}
	task->cpu_mask = *mask;
	return 0;
}

int sys_sched_getaffinity(pid_t pid, unsigned cpusetsize, cpu_set_t *mask){
	if(pid == 0){
		pid = cur_task->task_pid;
	}
	int perm_check = 1;
	if(cur_task == NULL) {
		perm_check = 0;
	} else{
		perm_check = cur_task->task_type == TASK_TYPE_USER;
	}
	struct task *task = pid2task(pid, perm_check);
	if (task == NULL){
		return -1;
	}
	*mask = task->cpu_mask;
	return 0;
}
