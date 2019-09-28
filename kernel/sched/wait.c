#include <types.h>
#include <error.h>

#include <kernel/mem.h>
#include <kernel/sched.h>

pid_t sys_wait(int *rstatus)
{
	/* LAB 5: your code here. */
	if(rstatus == NULL) {
		return -ECHILD;
	}

	return -ENOSYS;
}

pid_t sys_waitpid(pid_t pid, int *rstatus, int opts)
{
	/* LAB 5: your code here. */
	struct task *task = pid2task(pid, 1);
	if(!task || task == cur_task) {
		return -ECHILD;
	}

	return -ENOSYS;
}

