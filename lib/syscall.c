/* System call stubs. */

#include <syscall.h>
#include <lib.h>

extern int64_t do_syscall(uint64_t num, uint64_t a1, uint64_t a2,
	uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6);

static inline unsigned long syscall(int num, int check,
	unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4,
	unsigned long a5, unsigned long a6)
{
	unsigned long ret;

	/*
	 * Generic system call: pass system call number in AX,
	 * up to five parameters in DX, CX, BX, DI, SI.
	 * Interrupt kernel with T_SYSCALL.
	 *
	 * The "volatile" tells the assembler not to optimize
	 * this instruction away just because we don't use the
	 * return value.
	 *
	 * The last clause tells the assembler that this can
	 * potentially change the condition codes and arbitrary
	 * memory locations.
	 */
	ret = do_syscall(num, a1, a2, a3, a4, a5, a6);

	if(check && ret < 0) {
		panic("syscall %d returned %d (> 0)", num, ret);
	}

	return ret;
}

void puts(const char *s, size_t len)
{
	syscall(SYS_cputs, 0, (uintptr_t)s, len, 0, 0, 0, 0);
}

int getc(void)
{
	return syscall(SYS_cgetc, 0, 0, 0, 0, 0, 0, 0);
}

int kill(pid_t pid)
{
	return syscall(SYS_kill, 1, pid, 0, 0, 0, 0, 0);
}

pid_t getpid(void)
{
	 return syscall(SYS_getpid, 0, 0, 0, 0, 0, 0, 0);
}

int mquery(struct vma_info *info, void *addr)
{
	return syscall(SYS_mquery, 0, (uint64_t)info, (uint64_t)addr, 0, 0, 0, 0);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, uintptr_t offset)
{
	return (void *)syscall(SYS_mmap, 0, (uint64_t)addr, len, prot, flags, fd, offset);
}

void munmap(void *addr, size_t len)
{
	syscall(SYS_munmap, 0, (uint64_t)addr, len, 0, 0, 0, 0);
}

int mprotect(void *addr, size_t len, int prot)
{
	return syscall(SYS_mprotect, 0, (uint64_t)addr, len, prot, 0, 0, 0);
}

int madvise(void *addr, size_t len, int advice)
{
	return syscall(SYS_madvise, 0, (uint64_t)addr, len, advice, 0, 0, 0);
}

void sched_yield(void)
{
	syscall(SYS_yield, 0, 0, 0, 0, 0, 0, 0);
}

pid_t wait(int *rstatus)
{
	return syscall(SYS_wait, 0, (uint64_t)rstatus, 0, 0, 0, 0, 0);
}

pid_t waitpid(pid_t pid, int *rstatus, int opts)
{
	return syscall(SYS_waitpid, 0, (uint64_t)pid, (uint64_t)rstatus, opts, 0, 0, 0);
}

pid_t fork(void)
{
	return syscall(SYS_fork, 0, 0, 0, 0, 0, 0, 0);
}

unsigned int getcpuid(void)
{
	return syscall(SYS_getcpuid, 0, 0, 0, 0, 0, 0, 0);
}

#ifdef BONUS_LAB5
int exec(char *binary){
	return syscall(SYS_exec, 0, (uint64_t)binary, 0, 0, 0, 0, 0);
}
pid_t port_open(pid_t pid){
	return syscall(SYS_port_open, 0, (uint64_t)pid, 0, 0, 0, 0, 0);
}
int close(int fd){
	return syscall(SYS_close, 0, (uint64_t)fd, 0, 0, 0, 0, 0);
}
int read(int fd, void *buf, int nbyte){
	return syscall(SYS_read, 0, (uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, 0, 0, 0);
}
int write(int fd, const void *buf, int nbyte){
	return syscall(SYS_write, 0, (uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, 0, 0, 0);
}

#endif

#ifdef BONUS_LAB6
int sched_setaffinity(pid_t pid, unsigned cpusetsize, cpu_set_t *mask){
	return syscall(SYS_sched_setaffinity, 0, (uint64_t)pid, (uint64_t)cpusetsize, (uint64_t)mask, 0, 0, 0);
}
int sched_getaffinity(pid_t pid, unsigned cpusetsize, cpu_set_t *mask){
	return syscall(SYS_sched_getaffinity, 0, (uint64_t)pid, (uint64_t)cpusetsize, (uint64_t)mask, 0, 0, 0);
}
#endif

int test_swap_out(void *addr){
	return syscall(SYS_swap_out, 0, (uint64_t)addr, 0, 0, 0, 0, 0);
}
int test_swap_in(void *addr){
	return syscall(SYS_swap_in, 0, (uint64_t)addr, 0, 0, 0, 0, 0);
}