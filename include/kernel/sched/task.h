#pragma once

#include <task.h>
#include <cpu.h>

#define cur_task (this_cpu->cpu_task)

struct task *pid2task(pid_t pid, int check_perm);
void task_init(void);
void task_create(uint8_t *binary, enum task_type type);
void task_free(struct task *task);
void task_destroy(struct task *task);
void task_pop_frame(struct int_frame *frame);
void task_run(struct task *task);
struct task *task_alloc(pid_t ppid);
void task_remove_child(struct task *task);
#ifdef BONUS_LAB5
void task_load_elf(struct task *task, uint8_t *binary);
#endif
/* Without this extra macro, we couldn't pass macros like TEST to TASK_CREATE()
 * because of the C preprocessor's argument prescan rule.
 */
#define TASK_PASTE3(x, y, z) x ## y ## z

#define TASK_CREATE(x, type)                                             \
	do {                                                             \
		extern uint8_t TASK_PASTE3(_binary_obj_, x, _start)[];   \
		task_create(TASK_PASTE3(_binary_obj_, x, _start), type); \
	} while (0)

#ifdef BONUS_LAB5
#define RETURN_TASK_BINARY(binary, x) 										\
	do {															\
		if(strcmp(binary, #x) == 0) {								\
			extern uint8_t TASK_PASTE3(_binary_obj_user_, x, _start)[];	\
			return TASK_PASTE3(_binary_obj_user_, x, _start);			\
		}															\
	} while (0)
#endif

