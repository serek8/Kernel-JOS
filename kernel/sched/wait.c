#include <types.h>
#include <cpu.h>
#include <error.h>

#include <kernel/mem.h>
#include <kernel/sched.h>

pid_t sys_wait(int *rstatus)
{
	/* LAB 5: your code here. */
	if(rstatus == NULL) {
		return -ECHILD;
	}

	if(!list_is_empty(&cur_task->task_zombies)) {
		int task_pid = -ECHILD;
		struct list *node, *next;
		LOCK_TASK(cur_task);
		list_foreach_safe(&cur_task->task_zombies, node, next) {
			struct task *zombie = container_of(node, struct task, task_node);
			task_pid = zombie->task_pid;
			cprintf("[PID %5u] Reaping task with PID %d\n", cur_task->task_pid, task_pid);
			task_remove_child(zombie);
		}
		UNLOCK_TASK(cur_task);
		return task_pid;
	}

	// put into waiting state
	cur_task->task_status = TASK_NOT_RUNNABLE;
	cur_task = NULL;
	sched_yield();

	return -ENOSYS;
}

pid_t sys_waitpid(pid_t pid, int *rstatus, int opts)
{
	/* LAB 5: your code here. */
	struct task *task = pid2task(pid, 1);
	if(!task || task == cur_task) {
		return -ECHILD;
	}

	if(task->task_status == TASK_DYING) {
		int task_pid = task->task_pid;
		cprintf("[PID %5u] Reaping task with PID %d\n", cur_task->task_pid, task_pid);
		LOCK_TASK(cur_task);
		task_remove_child(task);
		UNLOCK_TASK(cur_task);
		return task_pid;
	}

	// put into waiting state
	cur_task->task_status = TASK_NOT_RUNNABLE;
	cur_task = NULL;
	sched_yield();

	return -ENOSYS;
}

