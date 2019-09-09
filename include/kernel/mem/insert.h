#pragma once

#include <types.h>
#include <paging.h>

struct insert_info {
	struct page_table *pml4;
	struct page_info *page;
	uint64_t flags;
};

int page_insert(struct page_table *pml4, struct page_info *page, void *va,
    uint64_t flags);

