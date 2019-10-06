#pragma once

void sched_init(void);
void sched_init_mp(void);
void sched_yield(void);
void sched_halt(void);

#ifdef USE_BIG_KERNEL_LOCK
	#define LOCK_RUNQ(runq) do { } while(0)
	#define UNLOCK_RUNQ(runq) do { } while(0)

	#define ADD_NEXTQ(task) do { } while(0)
#else
	#define LOCK_RUNQ(runq) do { spin_lock(&runq); } while(0)
	#define UNLOCK_RUNQ(runq) do { spin_unlock(&runq); } while(0)

	#define ADD_NEXTQ(task) do { if(task->task_type == TASK_TYPE_USER) { lrunq_len++; } list_push_left(&lnextq, &task->task_node); } while(0)
#endif