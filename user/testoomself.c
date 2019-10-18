#include <lib.h>
#include <string.h>


/*
 * Run with: SWAP_DISC_SIZE=12 and QEMUEXTRA="-m 15M" make run-testoomself-nox
 * Parent task fills up memory. 
 * OOM killer should kill parent task to free up memory.
 */
int main(int argc, char **argv)
{
	char *addr = (void *)0x1000000;
	char *ret;

	int child = fork();
	if(child == 0) {
		printf("Hello I'm the child\n");
		mmap(addr, HPAGE_SIZE, PROT_READ | PROT_WRITE,
	     MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
		for(int i=0; i<1000; i++) {
            sched_yield();
        }
        printf("Goodbye from child\n");
        return 0;
	}

    printf("Parent: Mapping until memory is full!\n");
	ret = mmap(addr, PAGE_SIZE*50000, PROT_READ | PROT_WRITE,
	     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert(ret == addr);

	for(int i=0; i<50000; i++) {
		memset(addr + PAGE_SIZE*i, i+16, PAGE_SIZE);
	}

	return 0;
}
