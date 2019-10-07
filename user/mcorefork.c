#include <lib.h>

int main(int argc, char **argv)
{
	pid_t pid;
	unsigned cpuid;
	size_t i;

	/* Fork a bunch of processes. */
	for (i = 0; i < 3; ++i) {
		printf("fork %d/2, pid=%d, cpu=%d\n", i, getpid(), getcpuid());
		fork();
	}

	pid = getpid();
	cpuid = getcpuid();

	printf("[PID %5u] Running on CPU %u\n", pid, cpuid);

	return 0;
}

