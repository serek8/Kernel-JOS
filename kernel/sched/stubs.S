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
	/* the processor pushes already a few things on the stack
			stack segment ss
			stack pointer rsp
			RFLAGS
			code segment cs
			instruction pointer rip
			error code (optional)
		then we push the following in the isr* handler:
			error code (if not pushed by processor)
			interrupt number
	*/

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
	mov %rax, %es

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


ISR_NOERRCODE int_no=0 // INT_DIVIDE
ISR_NOERRCODE int_no=1 // INT_DEBUG
ISR_NOERRCODE int_no=2 // INT_NMI
ISR_NOERRCODE int_no=3 // INT_BREAK
ISR_NOERRCODE int_no=4 // INT_OVERFLOW
ISR_NOERRCODE int_no=5 // INT_BOUND
ISR_NOERRCODE int_no=6 // INT_INVALID_OP
ISR_NOERRCODE int_no=7 // INT_DEVICE
ISR_ERRCODE int_no=8 // INT_DOUBLE_FAULT
ISR_NOERRCODE int_no=9
ISR_ERRCODE int_no=10 // INT_TSS
ISR_ERRCODE int_no=11 // INT_NO_SEG_PRESENT
ISR_ERRCODE int_no=12 // INT_SS
ISR_ERRCODE int_no=13 // INT_GPF
ISR_ERRCODE int_no=14 // INT_PAGE_FAULT
ISR_NOERRCODE int_no=15
ISR_NOERRCODE int_no=16 // INT_FPU
ISR_ERRCODE int_no=17 // INT_ALIGNMENT
ISR_NOERRCODE int_no=18 // INT_MCE
ISR_NOERRCODE int_no=19 // INT_SIMD
ISR_NOERRCODE int_no=20
ISR_NOERRCODE int_no=21
ISR_NOERRCODE int_no=22
ISR_NOERRCODE int_no=23
ISR_NOERRCODE int_no=24
ISR_NOERRCODE int_no=25
ISR_NOERRCODE int_no=26
ISR_NOERRCODE int_no=27
ISR_NOERRCODE int_no=28
ISR_NOERRCODE int_no=29
ISR_NOERRCODE int_no=30 // INT_SECURITY
ISR_NOERRCODE int_no=31
ISR_NOERRCODE int_no=32 // IRQ_TIMER
ISR_NOERRCODE int_no=33 // IRQ_KBD
ISR_NOERRCODE int_no=34
ISR_NOERRCODE int_no=35
ISR_NOERRCODE int_no=36 // IRQ_SERIAL
ISR_NOERRCODE int_no=37
ISR_NOERRCODE int_no=38
ISR_NOERRCODE int_no=39 // IRQ_SPURIOUS
ISR_NOERRCODE int_no=40
ISR_NOERRCODE int_no=41
ISR_NOERRCODE int_no=42
ISR_NOERRCODE int_no=43
ISR_NOERRCODE int_no=44
ISR_NOERRCODE int_no=45
ISR_NOERRCODE int_no=46 // IRQ_IDE
ISR_NOERRCODE int_no=47
ISR_NOERRCODE int_no=48
ISR_NOERRCODE int_no=49
ISR_NOERRCODE int_no=50
ISR_NOERRCODE int_no=51 // IRQ_ERROR
ISR_NOERRCODE int_no=52
ISR_NOERRCODE int_no=53
ISR_NOERRCODE int_no=54
ISR_NOERRCODE int_no=55
ISR_NOERRCODE int_no=56
ISR_NOERRCODE int_no=57
ISR_NOERRCODE int_no=58
ISR_NOERRCODE int_no=59
ISR_NOERRCODE int_no=60
ISR_NOERRCODE int_no=61
ISR_NOERRCODE int_no=62
ISR_NOERRCODE int_no=63
ISR_NOERRCODE int_no=64
ISR_NOERRCODE int_no=65
ISR_NOERRCODE int_no=66
ISR_NOERRCODE int_no=67
ISR_NOERRCODE int_no=68
ISR_NOERRCODE int_no=69
ISR_NOERRCODE int_no=70
ISR_NOERRCODE int_no=71
ISR_NOERRCODE int_no=72
ISR_NOERRCODE int_no=73
ISR_NOERRCODE int_no=74
ISR_NOERRCODE int_no=75
ISR_NOERRCODE int_no=76
ISR_NOERRCODE int_no=77
ISR_NOERRCODE int_no=78
ISR_NOERRCODE int_no=79
ISR_NOERRCODE int_no=80
ISR_NOERRCODE int_no=81
ISR_NOERRCODE int_no=82
ISR_NOERRCODE int_no=83
ISR_NOERRCODE int_no=84
ISR_NOERRCODE int_no=85
ISR_NOERRCODE int_no=86
ISR_NOERRCODE int_no=87
ISR_NOERRCODE int_no=88
ISR_NOERRCODE int_no=89
ISR_NOERRCODE int_no=90
ISR_NOERRCODE int_no=91
ISR_NOERRCODE int_no=92
ISR_NOERRCODE int_no=93
ISR_NOERRCODE int_no=94
ISR_NOERRCODE int_no=95
ISR_NOERRCODE int_no=96
ISR_NOERRCODE int_no=97
ISR_NOERRCODE int_no=98
ISR_NOERRCODE int_no=99
ISR_NOERRCODE int_no=100
ISR_NOERRCODE int_no=101
ISR_NOERRCODE int_no=102
ISR_NOERRCODE int_no=103
ISR_NOERRCODE int_no=104
ISR_NOERRCODE int_no=105
ISR_NOERRCODE int_no=106
ISR_NOERRCODE int_no=107
ISR_NOERRCODE int_no=108
ISR_NOERRCODE int_no=109
ISR_NOERRCODE int_no=110
ISR_NOERRCODE int_no=111
ISR_NOERRCODE int_no=112
ISR_NOERRCODE int_no=113
ISR_NOERRCODE int_no=114
ISR_NOERRCODE int_no=115
ISR_NOERRCODE int_no=116
ISR_NOERRCODE int_no=117
ISR_NOERRCODE int_no=118
ISR_NOERRCODE int_no=119
ISR_NOERRCODE int_no=120
ISR_NOERRCODE int_no=121
ISR_NOERRCODE int_no=122
ISR_NOERRCODE int_no=123
ISR_NOERRCODE int_no=124
ISR_NOERRCODE int_no=125
ISR_NOERRCODE int_no=126
ISR_NOERRCODE int_no=127
ISR_NOERRCODE int_no=128 // INT_SYSCALL
ISR_NOERRCODE int_no=129
ISR_NOERRCODE int_no=130
ISR_NOERRCODE int_no=131
ISR_NOERRCODE int_no=132
ISR_NOERRCODE int_no=133
ISR_NOERRCODE int_no=134
ISR_NOERRCODE int_no=135
ISR_NOERRCODE int_no=136
ISR_NOERRCODE int_no=137
ISR_NOERRCODE int_no=138
ISR_NOERRCODE int_no=139
ISR_NOERRCODE int_no=140
ISR_NOERRCODE int_no=141
ISR_NOERRCODE int_no=142
ISR_NOERRCODE int_no=143
ISR_NOERRCODE int_no=144
ISR_NOERRCODE int_no=145
ISR_NOERRCODE int_no=146
ISR_NOERRCODE int_no=147
ISR_NOERRCODE int_no=148
ISR_NOERRCODE int_no=149
ISR_NOERRCODE int_no=150
ISR_NOERRCODE int_no=151
ISR_NOERRCODE int_no=152
ISR_NOERRCODE int_no=153
ISR_NOERRCODE int_no=154
ISR_NOERRCODE int_no=155
ISR_NOERRCODE int_no=156
ISR_NOERRCODE int_no=157
ISR_NOERRCODE int_no=158
ISR_NOERRCODE int_no=159
ISR_NOERRCODE int_no=160
ISR_NOERRCODE int_no=161
ISR_NOERRCODE int_no=162
ISR_NOERRCODE int_no=163
ISR_NOERRCODE int_no=164
ISR_NOERRCODE int_no=165
ISR_NOERRCODE int_no=166
ISR_NOERRCODE int_no=167
ISR_NOERRCODE int_no=168
ISR_NOERRCODE int_no=169
ISR_NOERRCODE int_no=170
ISR_NOERRCODE int_no=171
ISR_NOERRCODE int_no=172
ISR_NOERRCODE int_no=173
ISR_NOERRCODE int_no=174
ISR_NOERRCODE int_no=175
ISR_NOERRCODE int_no=176
ISR_NOERRCODE int_no=177
ISR_NOERRCODE int_no=178
ISR_NOERRCODE int_no=179
ISR_NOERRCODE int_no=180
ISR_NOERRCODE int_no=181
ISR_NOERRCODE int_no=182
ISR_NOERRCODE int_no=183
ISR_NOERRCODE int_no=184
ISR_NOERRCODE int_no=185
ISR_NOERRCODE int_no=186
ISR_NOERRCODE int_no=187
ISR_NOERRCODE int_no=188
ISR_NOERRCODE int_no=189
ISR_NOERRCODE int_no=190
ISR_NOERRCODE int_no=191
ISR_NOERRCODE int_no=192
ISR_NOERRCODE int_no=193
ISR_NOERRCODE int_no=194
ISR_NOERRCODE int_no=195
ISR_NOERRCODE int_no=196
ISR_NOERRCODE int_no=197
ISR_NOERRCODE int_no=198
ISR_NOERRCODE int_no=199
ISR_NOERRCODE int_no=200
ISR_NOERRCODE int_no=201
ISR_NOERRCODE int_no=202
ISR_NOERRCODE int_no=203
ISR_NOERRCODE int_no=204
ISR_NOERRCODE int_no=205
ISR_NOERRCODE int_no=206
ISR_NOERRCODE int_no=207
ISR_NOERRCODE int_no=208
ISR_NOERRCODE int_no=209
ISR_NOERRCODE int_no=210
ISR_NOERRCODE int_no=211
ISR_NOERRCODE int_no=212
ISR_NOERRCODE int_no=213
ISR_NOERRCODE int_no=214
ISR_NOERRCODE int_no=215
ISR_NOERRCODE int_no=216
ISR_NOERRCODE int_no=217
ISR_NOERRCODE int_no=218
ISR_NOERRCODE int_no=219
ISR_NOERRCODE int_no=220
ISR_NOERRCODE int_no=221
ISR_NOERRCODE int_no=222
ISR_NOERRCODE int_no=223
ISR_NOERRCODE int_no=224
ISR_NOERRCODE int_no=225
ISR_NOERRCODE int_no=226
ISR_NOERRCODE int_no=227
ISR_NOERRCODE int_no=228
ISR_NOERRCODE int_no=229
ISR_NOERRCODE int_no=230
ISR_NOERRCODE int_no=231
ISR_NOERRCODE int_no=232
ISR_NOERRCODE int_no=233
ISR_NOERRCODE int_no=234
ISR_NOERRCODE int_no=235
ISR_NOERRCODE int_no=236
ISR_NOERRCODE int_no=237
ISR_NOERRCODE int_no=238
ISR_NOERRCODE int_no=239
ISR_NOERRCODE int_no=240
ISR_NOERRCODE int_no=241
ISR_NOERRCODE int_no=242
ISR_NOERRCODE int_no=243
ISR_NOERRCODE int_no=244
ISR_NOERRCODE int_no=245
ISR_NOERRCODE int_no=246
ISR_NOERRCODE int_no=247
ISR_NOERRCODE int_no=248
ISR_NOERRCODE int_no=249
ISR_NOERRCODE int_no=250
ISR_NOERRCODE int_no=251
ISR_NOERRCODE int_no=252
ISR_NOERRCODE int_no=253
ISR_NOERRCODE int_no=254
ISR_NOERRCODE int_no=255