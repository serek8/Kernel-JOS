#include <types.h>
#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/mem.h>

/* Sets up slab allocators for every multiple of SLAB_ALIGN bytes starting from
 * SLAB_ALIGN.
 */
int kmem_init(void)
{
	// cprintf("kmem_init_mp this_cpu=%d\n", this_cpu->cpu_id);
	nslabs = 32;

	struct slab *slab;
	size_t obj_size;
	size_t i;

	for (i = 0; i < nslabs; ++i) {
		slab = slabs + i;
		obj_size = (i + 1) * SLAB_ALIGN;
		slab_setup(slab, obj_size);
	}

	return 0;
}

int kmem_init_mp(void)
{
	/* LAB 6: your code here. */
	kmem_init();
	return 0;
}

/* Allocates a chunk of memory of size bytes.
 *
 * If the size is zero, this function returns NULL.
 * If the size is greater than or equal to the highest object size available in
 * the set of slab allocators, this function returns NULL.
 * Otherwise this function finds the best fit slab allocator for the requested
 * size and uses slab_alloc() to allocate the chunk of memory. */
void *kmalloc(size_t size)
{
	size_t index;

	if (size == 0) {
		return NULL;
	}

	size = ROUNDUP(size, SLAB_ALIGN);
	index = (size / SLAB_ALIGN) - 1;

	if (index >= nslabs) {
		panic("kmalloc is out of memory! index >= nslabs <==> %d >= %d\n", index, nslabs);
		return NULL;
	}
	// cprintf("allocated slabs=%d, index=%d", slabs, index);
	return slab_alloc(slabs + index);
}

/* This function calls slab_free() to free the chunk of memory. */
void kfree(void *p)
{
	slab_free(p);
}
