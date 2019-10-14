#include <lib.h>

int main(int argc, char **argv)
{
	pid_t pid = getpid();
	int i;

	printf("[PID %5u] Hello in swap test!\n", pid);

	char *addr = (void *)0x1000000;
	char *ret=  mmap(addr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	*addr = 0x51;
	int child = fork();
	if(child == 0){
		printf("[PID %5u] I am the child!\n", getpid());
		test_swap_out(addr);
		*addr = 0x61;
		printf("*0x1000000 = %p\n", *addr);
		test_swap_out(addr);
	} else{
		sched_yield();
		sched_yield();
		sched_yield();
		printf("[PID %5u] I am the parent!\n", getpid());
		test_swap_out(addr);
		printf("*0x1000000 = %p\n", *addr);
		// test_swap_out(addr);
	}


	printf("[PID %5u] I am done! Good bye!\n", getpid());

	return 0;
}

