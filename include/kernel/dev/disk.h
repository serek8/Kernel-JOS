#pragma once

#include <types.h>

struct disk;

struct disk_ops {
	int (* poll)(struct disk *);
	int64_t (* read)(struct disk *, void *, size_t, uint64_t);
	int64_t (* write)(struct disk *, const void *, size_t, uint64_t);
};

struct disk {
	struct disk_ops *ops;
};

#define MAX_DISKS 32

extern struct disk *disks[];
extern size_t ndisks;

int disk_poll(struct disk *disk);
int64_t disk_read(struct disk *disk, void *buf, size_t count, uint64_t addr);
int64_t disk_write(struct disk *disk, const void *buf, size_t count,
	uint64_t addr);

