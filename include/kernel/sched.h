#pragma once

#include <kernel/sched/fork.h>
#include <kernel/sched/gdt.h>
#include <kernel/sched/idt.h>
#include <kernel/sched/sched.h>
#include <kernel/sched/syscall.h>
#include <kernel/sched/task.h>
#include <kernel/sched/wait.h>

void sched_yield(void);
void sched_set_expired(void);