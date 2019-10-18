#include <kernel/swap/swap.h>

#include <stdio.h>
#include <kernel/sched.h>
#include <kernel/mem.h>
#include <task.h>
#include <kernel/dev/disk.h>
#include <kernel/dev/pci.h>
#include <string.h>
#include <error.h>

struct spinlock oom_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "oom_lock",
#endif
};

extern struct task **tasks;
extern pid_t pid_max;

void oom_init()
{
    spin_init(&oom_lock, "oom_lock");
}

static inline struct task *oom_get_next(pid_t start_pid)
{
    for (pid_t pid = start_pid+1; pid < pid_max; ++pid) {
		if (tasks[pid]) {
			return tasks[pid];
		}
	}
    return NULL;
}

static inline int oom_get_score(struct task *task)
{
    if(task->task_type == TASK_TYPE_KERNEL) {
        return 0;
    }

    int score = 0;
    score += task->task_active_pages*2;
    score += task->task_swapped_pages;

    // give zombies a bump of 5000 pages=20MB
    if(task->task_status == TASK_DYING && task->task_ppid != 0) {
        score += 5000; 
    }

    return score;
}

static void oom_print_scores()
{
    cprintf("----------\nOOM killer - badness scores\n\n");
    struct task *task = oom_get_next(0);
    while(task) {
        cprintf("PID=%2d, score=%4d, type=%s\n", 
            task->task_pid, 
            oom_get_score(task),
            task->task_type == TASK_TYPE_KERNEL ? "TASK_TYPE_KERNEL":"TASK_TYPE_USER");
        task = oom_get_next(task->task_pid);
    }
    cprintf("\n----------\n");
}

int oom_kill()
{
    spin_lock(&oom_lock);
    oom_print_scores();

    // determine which task to kill
    int score, bad_max = 0;
    struct task *bad_task = NULL;
    struct task *task = oom_get_next(0);
    while(task) {
        if(task->task_type != TASK_TYPE_KERNEL) {
            score = oom_get_score(task);
            if(score > bad_max) {
                bad_max = score;
                bad_task = task;
            }
        }
        task = oom_get_next(task->task_pid);
    }

    if(!bad_task) {
        spin_unlock(&oom_lock);
        return -1;
    }

    cprintf("OOM: killing task=%d, badness=%d\n", bad_task->task_pid, bad_max);

    task_destroy(bad_task);

    if(bad_task->task_status == TASK_DYING && bad_task->task_ppid != 0) {
		struct task *parent = pid2task(bad_task->task_ppid, 0);
		cprintf("[PID %5u] Reaping task with PID %d\n", cur_task->task_pid, bad_task->task_pid);
		LOCK_TASK(parent);
		task_remove_child(bad_task);
		UNLOCK_TASK(parent);
    }
    
    spin_unlock(&oom_lock);
    return 0;
}