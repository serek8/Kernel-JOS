#include <atomic.h>
#include <cpu.h>
#include <spinlock.h>

#include <x86-64/asm.h>

#include <kernel/acpi.h>

#ifdef USE_BIG_KERNEL_LOCK
/* The big kernel lock */
struct spinlock kernel_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "kernel_lock"
#endif
};
#endif

static int holding(struct spinlock *lock)
{
	return lock->locked && lock->cpu == this_cpu;
}

void spin_init(struct spinlock *lock, const char *name)
{
	lock->locked = 0;

#ifdef DEBUG_SPINLOCK
	lock->name = name;
	lock->cpu = NULL;
#endif
}

void __spin_lock(struct spinlock *lock, const char *file, int line)
{
#ifdef DEBUG_SPINLOCK
	if (holding(lock)) {
		panic("%s: %d: cpu %2d: attempt to lock %s twice\n",
			file, line,
			lapic_cpunum(), 
			lock->name ? lock->name : "anonymous",
			lapic_cpunum());
	}
#endif

	while (!atomic_cmpxchg(&lock->locked, 0, 1));

	atomic_barrier();

#ifdef DEBUG_SPINLOCK
	lock->cpu = this_cpu;
#endif
}

int __spin_trylock(struct spinlock *lock, const char *file, int line)
{
#ifdef DEBUG_SPINLOCK
	if (holding(lock)) {
		panic("%s:%d: cpu %2d: attempt to lock %s twice\n",
			file, line,
			lapic_cpunum(),
			lock->name ? lock->name : "anonymous",
			lapic_cpunum());
	}
#endif

	if (!atomic_cmpxchg(&lock->locked, 0, 1)) {
		return 0;
	}

	atomic_barrier();

#ifdef DEBUG_SPINLOCK
	lock->cpu = this_cpu;
#endif

	return 1;
}

void __spin_unlock(struct spinlock *lock, const char *file, int line)
{
#ifdef DEBUG_SPINLOCK
	if (!holding(lock)) {
		panic("%s:%d: cpu %2d: attempt to unlock %s owned by cpu %2d\n",
			file, line,
			lapic_cpunum(),
			lock->name ? lock->name : "anonymous",
			lapic_cpunum());
	}

	lock->cpu = NULL;
#endif

	atomic_barrier();
	lock->locked = 0;
}

