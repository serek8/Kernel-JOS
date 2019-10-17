#include <lib.h>


#include <lib.h>
#include <string.h>

int main(int argc, char **argv)
{
	struct vma_info info;
	char *addr = (void *)0x1000000;

	mmap(addr, HPAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
	for(int i=0; i<512; i++){
		uint64_t *a = (uint64_t*)(addr + i*PAGE_SIZE);
		*a = i+1;
	}
	// memset(addr, 1, HPAGE_SIZE);

	test_swap_out(addr); 
	mprotect(addr+PAGE_SIZE, PAGE_SIZE, PROT_READ);
	for(int i=0; i<512; i++){
		uint64_t *a = (uint64_t*)(addr + i*PAGE_SIZE);
		printf("i <=> %u\n", *a);
	}
	

	mquery(&info, addr);

	switch (info.vm_mapped) {
		case VM_UNMAPPED: printf("unmapped\n"); break;
		case VM_4K_PAGE: printf("4K page\n"); break;
		case VM_2M_PAGE: printf("2M page\n"); break;
	}

	print_vmas();

	printf("loop\n");
	// while(1);

	return 0;
}

// int main(int argc, char **argv)
// {
// 	pid_t pid = getpid();
// 	int i;

// 	printf("[PID %5u] Hello in swap test!\n", pid);

// 	uint8_t *addr = (void *)0x1000000;
// 	mmap(addr, HPAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
// 	int a=0;
// 	for(int i=0; i<512; i++){
// 		*(addr + i*PAGE_SIZE) = i+1;
// 	}
// 	test_swap_out(addr); 
// 	// test_swap_out(addr); 
// 	printf("*0x1000000 = %p\n", *addr);
// 	printf("[PID %5u] I am done! Good bye!\n", getpid());

// 	return 0;
// }

// // Merge big pages and swap out
// int main(int argc, char **argv)
// {
// 	printf("[PID %5u] Hello in swap test!\n", getpid());
// 	uint8_t *addr = (void *)0x1000000;
	
// 	for (int i = 0; i < 10; ++i) if (fork() == 0) break;
	
// 	mmap(addr, HPAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	
// 	int a=0;
// 	for(int i=0; i<512; i++){
// 		*(addr + i*PAGE_SIZE) = i+1;
// 	}
	
// 	test_swap_out(addr+PAGE_SIZE); 
// 	printf("*0x1000000 = %p\n", *addr);
// 	printf("[PID %5u] I am done! Good bye!\n", getpid());

// 	return 0;
// }


// // // Merge big pages
// int main(int argc, char **argv)
// {
// 	pid_t pid = getpid();
// 	int i;

// 	printf("[PID %5u] Hello in swap test!\n", pid);

// 	uint8_t *addr = (void *)0x1000000;
// 	mmap(addr, HPAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
// 	int a=0;
// 	for(int i=0; i<512; i++){
// 		*(addr + i*PAGE_SIZE) = i;
// 	}
// 	test_swap_out(addr); 
// 	// printf("*0x1000000 = %p\n", *addr);
// 	printf("[PID %5u] I am done! Good bye!\n", getpid());

// 	return 0;
// }


// // // Big pages swaps
// int main(int argc, char **argv)
// {
// 	pid_t pid = getpid();
// 	int i;

// 	printf("[PID %5u] Hello in swap test!\n", pid);

// 	char *addr = (void *)0x1000000;
// 	char *addr2 = (void *)0x1010000;
// 	mmap(addr, HPAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
// 	// mmap(addr2, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
// 	*addr = 0x51;
// 	// *addr2 = 0x52;
// 	test_swap_out(addr); 
// 	// test_swap_out(addr2);
// 	printf("*0x1000000 = %p\n", *addr);
// 	// printf("*0x1001000 = %p\n", *addr2);

// 	printf("[PID %5u] I am done! Good bye!\n", getpid());

// 	return 0;
// }

// Maultiple swaps
// int main(int argc, char **argv)
// {
// 	pid_t pid = getpid();
// 	int i;

// 	printf("[PID %5u] Hello in swap test!\n", pid);

// 	char *addr = (void *)0x1000000;
// 	char *addr2 = (void *)0x1001000;
// 	mmap(addr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
// 	mmap(addr2, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
// 	*addr = 0x51;
// 	*addr2 = 0x52;
// 	test_swap_out(addr); 
// 	test_swap_out(addr2);
// 	printf("*0x1000000 = %p\n", *addr);
// 	printf("*0x1001000 = %p\n", *addr2);

// 	printf("[PID %5u] I am done! Good bye!\n", getpid());

// 	return 0;
// }


// COW
// int main(int argc, char **argv)
// {
// 	pid_t pid = getpid();
// 	int i;

// 	printf("[PID %5u] Hello in swap test!\n", pid);

// 	char *addr = (void *)0x1000000;
// 	char *ret=  mmap(addr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
// 	*addr = 0x51;
// 	int child = fork();
// 	if(child == 0){
// 		printf("[PID %5u] I am the child!\n", getpid());
// 		test_swap_out(addr);
// 		*addr = 0x61;
// 		printf("*0x1000000 = %p\n", *addr);
// 		test_swap_out(addr);
// 	} else{
// 		sched_yield();
// 		sched_yield();
// 		sched_yield();
// 		printf("[PID %5u] I am the parent!\n", getpid());
// 		test_swap_out(addr);
// 		printf("*0x1000000 = %p\n", *addr);
// 		// test_swap_out(addr);
// 	}
// 	printf("[PID %5u] I am done! Good bye!\n", getpid());
// 	return 0;
// }





// swap out before fork
// int main(int argc, char **argv)
// {
// 	pid_t pid = getpid();
// 	int i;

// 	printf("[PID %5u] Hello in swap test!\n", pid);

// 	char *addr = (void *)0x1000000;
// 	char *ret=  mmap(addr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
// 	*addr = 0x51;
// 	test_swap_out(addr); // swap out before fork
// 	int child = fork();
// 	if(child == 0){
// 		printf("[PID %5u] I am the child!\n", getpid());
// 		test_swap_out(addr);
// 		*addr = 0x61;
// 		printf("*0x1000000 = %p\n", *addr);
// 		// test_swap_out(addr);
// 	} else{
// 		sched_yield();
// 		sched_yield();
// 		sched_yield();
// 		printf("[PID %5u] I am the parent!\n", getpid());
// 		test_swap_out(addr);
// 		printf("*0x1000000 = %p\n", *addr);
// 		// test_swap_out(addr);
// 	}
// 	printf("[PID %5u] I am done! Good bye!\n", getpid());
// 	return 0;
// }
