#pragma once

#include <types.h>
#include <paging.h>

void populate_region(struct page_table *pml4, void *va, size_t size,
	uint64_t flags, struct task *taskx);
void populate_region_user(struct page_table *pml4, void *va, size_t size,
	uint64_t flags, struct task *taskx, int user_page);
