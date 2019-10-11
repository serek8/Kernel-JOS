#include <kernel/swap/swap.h>
#include <stdio.h>


int swap_out(struct page_info *page){
    cprintf("hello from swap_out\n");
    return -1;
}

int swap_in(uint64_t swap_index){
    cprintf("hello from swap_in\n");

    return -1;
}