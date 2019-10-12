#include <lib.h>

int main(int argc, char **argv)
{
	pid_t pid = getpid();
	int i;

	printf("[PID %5u] Hello in swap test!\n", pid);

	char *addr = (void *)0x1000000;
	char *ret;
	ret = mmap(addr, PAGE_SIZE, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	// assert(ret == addr);
	// memset(addr, 0, PAGE_SIZE);
	printf("*0x1000000 = %p\n", *addr);

	test_swap_out(addr);
	// test_swap_in(addr);
	// printf("will fork\n");
	int child = fork();
	if(child == 0){
		printf("[PID %5u] I am the child!\n", getpid());
		printf("*0x1000000 = %p\n", *addr);
		test_swap_out(addr);
	} else{
		sched_yield();
		sched_yield();
		sched_yield();
		// printf("[PID %5u] I am the parent!\n", getpid());
		// test_swap_out(addr);
	}


	printf("[PID %5u] I am done! Good bye!\n", pid);

	return 0;
}

