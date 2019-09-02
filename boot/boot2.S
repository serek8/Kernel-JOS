#include <x86/asm.h>
#include <x86/gdt.h>

.code16
.section .text

.global boot2
boot2:
	/* Enable the A20 line. */
	call set_a20
	jnc 1f
	movw $error_a20, %si
	call puts
	hlt

1:
	/* Get the memory map. */
	movw $0x500, %di
	movw %di, mmap_addr
	call get_mmap_e820
	movw %bp, mmap_count

	/* Enable protected mode. */
	movl %cr0, %eax
	orl $CR0_PM, %eax
	movl %eax, %cr0

	/* Load the global descriptor table and set up the segment registers. */
	lgdt gdtr

	movw $GDT_KDATA, %ax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %fs
	movw %ax, %gs
	movw %ax, %ss
	ljmp $GDT_KCODE, $boot32

.code32
boot32:
	pushl $boot_info
	call bootmain
	hlt

.section .data

boot_info:
mmap_addr: .long 0
mmap_count: .long 0

.balign 8
gdt:
	/* Null descriptor. */
	.word 0
	.word 0
	.byte 0
	.word 0
	.byte 0

	/* Kernel code descriptor. */
	.word 0xFFFF
	.word 0
	.byte 0
	.word GDT_KCODE_FLAGS | GDT_SIZE | GDT_GRANULARITY | GDT_LIMIT(0xF)
	.byte 0

	/* Kernel data descriptor. */
	.word 0xFFFF
	.word 0
	.byte 0
	.word GDT_KDATA_FLAGS | GDT_SIZE | GDT_GRANULARITY | GDT_LIMIT(0xF)
	.byte 0

gdtr:
	.word . - gdt - 1
	.long gdt

.section .rodata

.global test
error_a20: .ascii "error: unable to enable the A20 line.\r\n\0"

