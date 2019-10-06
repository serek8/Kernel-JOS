#pragma once

#include <types.h>
#include <list.h>
#include <rbtree.h>
#include <spinlock.h>

#include <x86-64/idt.h>
#include <x86-64/memory.h>

typedef int32_t pid_t;

#define FILE_DESCRIPTION_TABLE_SIZE 2
#define FD_OPEN (1 << 0)
#define FD_READY (1 << 1) // the reader or writer is already waiting for copying data 
#define FD_DONE (1 << 2) 
#define FD_ERROR (1 << 3) 

#define TASK_CPU_PINNING_ANY -1

typedef struct {
  uint64_t bits;
} cpu_set_t;

#define CPU_ZERO(set) set.bits = 0;
#define CPU_SET(set, cpu) set.bits |= (1 << cpu);
#define CPU_SET_ALL(set) set.bits = ~0;
#define CPU_CLR(set, cpu) set.bits &= ~(1 << cpu);
#define CPU_ISSET(set, cpu) ((set.bits & (1 << cpu)) != 0);


/* Values of task_status in struct task. */
enum {
	TASK_DYING = 0,
	TASK_RUNNABLE,
	TASK_RUNNING,
	TASK_NOT_RUNNABLE,
};

/* The method of interrupt used to switch to the kernel. */
enum {
	TASK_INT = 0,
	TASK_SYSCALL,
};

/* Special task types. */
enum task_type {
	TASK_TYPE_USER = 0,
	TASK_TYPE_KERNEL,
};

struct fd {
	pid_t pid; // writer PID
	uint64_t flags;
	void *bytes;
	uint64_t nbytes;
};

struct task {
	/* The saved registers. */
	struct int_frame task_frame;

	/* The task this task is waiting on. */
	struct task *task_wait;

	/* The process ID of this task and its parent. */
	pid_t task_pid;
	pid_t task_ppid;

	/* The task type. */
	enum task_type task_type;

	/* The task status. */
	unsigned task_status;

	/* The number of times the task has been run. */
	unsigned task_runs;

	/* The CPU that the task is running on. */
	int task_cpunum;

	/* Pinned cpus. */
	cpu_set_t cpu_mask;

	/* The virtual address space. */
	struct page_table *task_pml4;

	/* The VMAs */
	struct rb_tree task_rb;
	struct list task_mmap;

	/* The children */
	struct list task_children;
	struct list task_child;

	/* The zombies */
	struct list task_zombies;

	/* The anchor node (for zombies or the run queue) */
	struct list task_node;

#ifndef USE_BIG_KERNEL_LOCK
	/* Per-task lock */
	struct spinlock task_lock;
#endif
	uint64_t schedule_ts;
#ifdef BONUS_LAB5
	struct fd fd_table[FILE_DESCRIPTION_TABLE_SIZE];
#endif
};

