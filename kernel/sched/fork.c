#include <error.h>
#include <list.h>

#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

extern struct list runq;
extern pid_t pid_max;
extern struct task **tasks;

/* Allocates a task struct for the child process and copies the register state,
 * the VMAs and the page tables. Once the child task has been set up, it is
 * added to the run queue.
 */
struct task *task_clone(struct task *task)
{
	/* LAB 5: your code here. */
	struct task *clone = kmalloc(sizeof *task);
	if (!task) {
		return NULL;
	}

	// Set general stuff
	clone->task_type = task->task_type;
	clone->task_status = TASK_RUNNABLE;
	clone->task_runs = 0;
	// clone->task_cpunum - TODO: what to do?

	// Set pid and ppid
	/* Find a free PID for the task in the PID mapping and associate the
	 * task with that PID. */
	pid_t pid;
	for (pid = 1; pid < pid_max; ++pid) {
		if (!tasks[pid]) {
			tasks[pid] = task;
			clone->task_pid = pid;
			break;
		}
	}
	/* We are out of PIDs. */
	if (pid == pid_max) {
		kfree(task);
		return NULL;
	}
	clone->task_ppid = task->task_pid;


	// Copy frame/register state and set RAX=0 to signal this is child
	clone->task_frame = task->task_frame;
	clone->task_frame.rax = 0;

	// TODO: Copy page tables

	// TODO: Copy VMAs
	list_init(&clone->task_mmap);
	rb_init(&clone->task_rb);

	// Init lists
	list_init(&clone->task_children);
	list_init(&clone->task_child);
	list_init(&clone->task_zombies);

	// Add to the run queue
	list_init(&clone->task_node);
	list_push(&runq, &clone->task_node);

	return clone;
}

pid_t sys_fork(void)
{
	/* LAB 5: your code here. */
	struct task *clone = task_clone(cur_task);
	if(clone == NULL) {
		panic("Could not clone task!");
	}
	
	return clone->task_pid;
}

