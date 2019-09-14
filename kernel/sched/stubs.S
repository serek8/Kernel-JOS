.section .text

#include <x86-64/gdt.h>
#include <x86-64/idt.h>
#include <x86-64/memory.h>

#include <cpu.h>

.macro ISR_NOERRCODE int_no
.global isr\int_no
isr\int_no:
	pushq $0
	pushq $\int_no
	jmp isr_common_stub
.endm

.macro ISR_ERRCODE int_no
.global isr\int_no
isr\int_no:
	pushq $\int_no
	jmp isr_common_stub
.endm

isr_common_stub:
	/* LAB 3: your code here. */
	/* Save the register state on the stack. */

	pushq %rax
	pushq %rcx
	pushq %rdx
	pushq %rbx
	pushq %rbp
	pushq %rsi
	pushq %rdi
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	mov %ds, %rax // %cs
	pushq %rax

	/* Recover the segments. */
	movq $GDT_KDATA, %rax
	mov %rax, %ds
	mov %rax, %ss

	/* Jump to the generic interrupt handler. */
	movq %rsp, %rdi
	jmp int_handler

.global syscall64
syscall64:
	/* LAB 3: your code here. */
	/* Store the userspace stack pointer in the per-cpu struct. */

	/* Load the kernel stack pointer from the per-cpu struct. */

	/* Store the register state into the per-cpu struct. */

	/* Jump to the system call handler. */
	movq %r10, %rcx
	pushq %rbp
	pushq $0
	jmp syscall_handler

.global iret64
iret64:
	/* Restore the register state. */
	/* Return from the interrupt. */
	/* LAB 3: your code here. */


	// Now the stack is misaligned by 8 bytes because 'call' instruction saved %rip on the stack
	sub $56, %rsp  // alignment 8 + 56 = 64. Which is dividable by 16, thus aligned!

	movq 144(%rdi), %rax // rip at 18 postition
	movq %rax, (%rsp)

	movq 152(%rdi), %rax // cs at 19 postition
	movq %rax, 8(%rsp)

	movq 160(%rdi), %rax // rflags at 20 postition
	movq %rax, 16(%rsp)

	movq 168(%rdi), %rax // rsp at 21 postition
	movq %rax, 24(%rsp)

	movq 176(%rdi), %rax // ss at 22 postition
	movq %rax, 32(%rsp)

	
	movq 8(%rdi), %r15
	movq 16(%rdi), %r14
	movq 24(%rdi), %r13
	movq 32(%rdi), %r12
	movq 40(%rdi), %r11
	movq 48(%rdi), %r10
	movq 56(%rdi), %r9
	movq 64(%rdi), %r8
	// %rdi will be later on because it stores the ptr to int_frame
	movq 80(%rdi), %rsi
	movq 88(%rdi), %rbp
	movq 96(%rdi), %rbx
	movq 104(%rdi), %rdx
	movq 112(%rdi), %rcx

	movq 0(%rdi), %rax
	mov %rax, %ds

	movq 120(%rdi), %rax

	movq 72(%rdi), %rdi

	iretq

.global sysret64
sysret64:
	/* LAB 3: your code here. */
	/* Recover the register state. */

	/* Return from the system call. */
	sysretq


.global isr0
isr0:
	pushq $0
	pushq $0
	jmp isr_common_stub