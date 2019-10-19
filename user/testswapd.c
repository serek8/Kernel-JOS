#include <lib.h>
#include <string.h>


/*
 * Run with: SWAP_DISC_SIZE=12 and QEMUEXTRA="-m 15M" make run-swapd-nox
 * Task fills up memory. 
 * 
 */
int main(int argc, char **argv)
{
    int pages = 400;
	char *addr = (void *)0x1000000;
    if(fork() == 0){
        fork();
    }
    printf("Mapping until memory is almost full!\n");
    for(int i=0; i<PAGE_SIZE*2*pages; i+=PAGE_SIZE*2) {
        addr += i;
        // printf("%d: page=%p, PID=%d cpu=%d\n", i/(PAGE_SIZE*2), addr, getpid(), getcpuid());
	    mmap(addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
	        MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    }
    printf("Finished mapping %d*4K pages, going in while loop!\n", pages);
    while(1) {};

	return 0;
}
