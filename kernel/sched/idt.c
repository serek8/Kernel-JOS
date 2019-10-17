#include <assert.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/gdt.h>
#include <x86-64/idt.h>

#include <kernel/acpi.h>
#include <kernel/sched/idt.h>
#include <kernel/monitor.h>
#include <kernel/sched/syscall.h>
#include <kernel/sched/sched.h>
#include <kernel/acpi/lapic.h>

#include <kernel/sched/task.h>
#include <kernel/vma.h>
#include <spinlock.h>

static const char *int_names[256] = {
	[INT_DIVIDE] = "Divide-by-Zero Error Exception (#DE)",
	[INT_DEBUG] = "Debug (#DB)",
	[INT_NMI] = "Non-Maskable Interrupt",
	[INT_BREAK] = "Breakpoint (#BP)",
	[INT_OVERFLOW] = "Overflow (#OF)",
	[INT_BOUND] = "Bound Range (#BR)",
	[INT_INVALID_OP] = "Invalid Opcode (#UD)",
	[INT_DEVICE] = "Device Not Available (#NM)",
	[INT_DOUBLE_FAULT] = "Double Fault (#DF)",
	[INT_TSS] = "Invalid TSS (#TS)",
	[INT_NO_SEG_PRESENT] = "Segment Not Present (#NP)",
	[INT_SS] = "Stack (#SS)",
	[INT_GPF] = "General Protection (#GP)",
	[INT_PAGE_FAULT] = "Page Fault (#PF)",
	[INT_FPU] = "x86 FPU Floating-Point (#MF)",
	[INT_ALIGNMENT] = "Alignment Check (#AC)",
	[INT_MCE] = "Machine Check (#MC)",
	[INT_SIMD] = "SIMD Floating-Point (#XF)",
	[INT_SECURITY] = "Security (#SX)",
};

static struct idt_entry entries[256];
static struct idtr idtr = {
	.limit = sizeof(entries) - 1,
	.entries = entries,
};

static const char *get_int_name(unsigned int_no)
{
	if (!int_names[int_no])
		return "Unknown Interrupt";

	return int_names[int_no];
}

void print_int_frame(struct int_frame *frame)
{
	cprintf("INT frame at %p\n", frame);

	/* Print the interrupt number and the name. */
	cprintf(" INT %u: %s\n",
		frame->int_no,
		get_int_name(frame->int_no));

	/* Print the error code. */
	switch (frame->int_no) {
	case INT_PAGE_FAULT:
		cprintf(" CR2 %p\n", read_cr2());
		cprintf(" ERR 0x%016llx (%s, %s, %s)\n",
			frame->err_code,
			frame->err_code & 4 ? "user" : "kernel",
			frame->err_code & 2 ? "write" : "read",
			frame->err_code & 1 ? "protection" : "not present");
		break;
	default:
		cprintf(" ERR 0x%016llx\n", frame->err_code);
	}

	/* Print the general-purpose registers. */
	cprintf(" RAX 0x%016llx"
		" RCX 0x%016llx"
		" RDX 0x%016llx"
		" RBX 0x%016llx\n"
		" RSP 0x%016llx"
		" RBP 0x%016llx"
		" RSI 0x%016llx"
		" RDI 0x%016llx\n"
		" R8  0x%016llx"
		" R9  0x%016llx"
		" R10 0x%016llx"
		" R11 0x%016llx\n"
		" R12 0x%016llx"
		" R13 0x%016llx"
		" R14 0x%016llx"
		" R15 0x%016llx\n",
		frame->rax, frame->rcx, frame->rdx, frame->rbx,
		frame->rsp, frame->rbp, frame->rsi, frame->rdi,
		frame->r8,  frame->r9,  frame->r10, frame->r11,
		frame->r12, frame->r13, frame->r14, frame->r15);

	/* Print the IP, segment selectors and the RFLAGS register. */
	cprintf(" RIP 0x%016llx"
		" RFL 0x%016llx\n"
		" CS  0x%04x"
		"            "
		" DS  0x%04x"
		"            "
		" SS  0x%04x\n",
		frame->rip, frame->rflags,
		frame->cs, frame->ds, frame->ss);
}

/* Set up the interrupt handlers. */
void idt_init(void)
{
	/* LAB 3: your code here. */
	unsigned flags = IDT_PRESENT | IDT_PRIVL(3) | IDT_GATE(0) | IDT_INT_GATE32;
	unsigned flags_ring0 = IDT_PRESENT | IDT_PRIVL(0) | IDT_GATE(0) | IDT_INT_GATE32;

	set_idt_entry(&entries[INT_DIVIDE], isr0, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[1], isr1, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[2], isr2, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[INT_BREAK], isr3, flags, GDT_KCODE);
	set_idt_entry(&entries[4], isr4, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[5], isr5, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[6], isr6, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[7], isr7, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[8], isr8, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[9], isr9, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[10], isr10, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[11], isr11, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[12], isr12, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[13], isr13, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[14], isr14, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[15], isr15, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[16], isr16, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[17], isr17, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[18], isr18, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[19], isr19, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[20], isr20, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[21], isr21, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[22], isr22, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[23], isr23, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[24], isr24, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[25], isr25, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[26], isr26, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[27], isr27, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[28], isr28, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[29], isr29, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[30], isr30, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[31], isr31, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[32], isr32, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[33], isr33, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[34], isr34, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[35], isr35, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[36], isr36, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[37], isr37, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[38], isr38, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[39], isr39, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[40], isr40, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[41], isr41, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[42], isr42, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[43], isr43, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[44], isr44, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[45], isr45, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[46], isr46, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[47], isr47, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[48], isr48, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[49], isr49, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[50], isr50, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[51], isr51, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[52], isr52, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[53], isr53, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[54], isr54, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[55], isr55, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[56], isr56, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[57], isr57, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[58], isr58, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[59], isr59, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[60], isr60, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[61], isr61, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[62], isr62, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[63], isr63, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[64], isr64, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[65], isr65, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[66], isr66, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[67], isr67, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[68], isr68, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[69], isr69, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[70], isr70, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[71], isr71, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[72], isr72, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[73], isr73, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[74], isr74, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[75], isr75, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[76], isr76, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[77], isr77, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[78], isr78, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[79], isr79, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[80], isr80, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[81], isr81, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[82], isr82, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[83], isr83, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[84], isr84, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[85], isr85, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[86], isr86, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[87], isr87, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[88], isr88, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[89], isr89, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[90], isr90, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[91], isr91, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[92], isr92, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[93], isr93, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[94], isr94, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[95], isr95, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[96], isr96, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[97], isr97, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[98], isr98, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[99], isr99, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[100], isr100, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[101], isr101, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[102], isr102, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[103], isr103, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[104], isr104, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[105], isr105, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[106], isr106, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[107], isr107, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[108], isr108, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[109], isr109, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[110], isr110, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[111], isr111, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[112], isr112, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[113], isr113, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[114], isr114, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[115], isr115, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[116], isr116, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[117], isr117, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[118], isr118, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[119], isr119, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[120], isr120, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[121], isr121, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[122], isr122, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[123], isr123, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[124], isr124, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[125], isr125, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[126], isr126, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[127], isr127, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[INT_SYSCALL], isr128, flags, GDT_KCODE);
	set_idt_entry(&entries[129], isr129, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[130], isr130, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[131], isr131, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[132], isr132, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[133], isr133, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[134], isr134, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[135], isr135, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[136], isr136, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[137], isr137, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[138], isr138, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[139], isr139, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[140], isr140, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[141], isr141, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[142], isr142, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[143], isr143, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[144], isr144, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[145], isr145, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[146], isr146, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[147], isr147, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[148], isr148, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[149], isr149, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[150], isr150, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[151], isr151, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[152], isr152, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[153], isr153, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[154], isr154, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[155], isr155, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[156], isr156, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[157], isr157, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[158], isr158, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[159], isr159, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[160], isr160, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[161], isr161, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[162], isr162, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[163], isr163, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[164], isr164, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[165], isr165, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[166], isr166, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[167], isr167, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[168], isr168, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[169], isr169, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[170], isr170, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[171], isr171, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[172], isr172, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[173], isr173, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[174], isr174, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[175], isr175, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[176], isr176, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[177], isr177, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[178], isr178, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[179], isr179, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[180], isr180, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[181], isr181, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[182], isr182, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[183], isr183, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[184], isr184, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[185], isr185, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[186], isr186, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[187], isr187, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[188], isr188, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[189], isr189, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[190], isr190, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[191], isr191, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[192], isr192, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[193], isr193, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[194], isr194, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[195], isr195, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[196], isr196, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[197], isr197, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[198], isr198, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[199], isr199, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[200], isr200, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[201], isr201, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[202], isr202, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[203], isr203, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[204], isr204, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[205], isr205, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[206], isr206, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[207], isr207, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[208], isr208, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[209], isr209, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[210], isr210, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[211], isr211, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[212], isr212, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[213], isr213, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[214], isr214, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[215], isr215, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[216], isr216, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[217], isr217, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[218], isr218, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[219], isr219, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[220], isr220, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[221], isr221, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[222], isr222, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[223], isr223, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[224], isr224, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[225], isr225, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[226], isr226, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[227], isr227, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[228], isr228, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[229], isr229, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[230], isr230, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[231], isr231, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[232], isr232, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[233], isr233, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[234], isr234, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[235], isr235, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[236], isr236, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[237], isr237, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[238], isr238, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[239], isr239, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[240], isr240, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[241], isr241, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[242], isr242, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[243], isr243, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[244], isr244, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[245], isr245, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[246], isr246, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[247], isr247, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[248], isr248, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[249], isr249, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[250], isr250, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[251], isr251, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[252], isr252, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[253], isr253, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[254], isr254, flags_ring0, GDT_KCODE);
	set_idt_entry(&entries[255], isr255, flags_ring0, GDT_KCODE);
	
	load_idt(&idtr);
}

void idt_init_mp(void)
{
	/* LAB 6: your code here. */
	idt_init();
}

void int_dispatch(struct int_frame *frame)
{
	/* Handle processor exceptions:
	 *  - Fall through to the kernel monitor on a breakpoint.
	 *  - Dispatch page faults to page_fault_handler().
	 *  - Dispatch system calls to syscall().
	 */
	/* LAB 3: your code here. */
	switch (frame->int_no) {
		case INT_SYSCALL:
			// x86_64 Linux function calls: RDI, RSI, RDX, RCX, R8, R9, XMM0–7
			// lib/syscall.c:syscall -> calls lib/stub.S:do_syscall and arguments are just forwarded
			// therefore the last parameter would be in XMM0 which we don't save in frame
			frame->rax = syscall(frame->rdi, frame->rsi, frame->rdx, frame->rcx, frame->r8, frame->r9, frame->rbp);
			return;
		case INT_PAGE_FAULT:
			page_fault_handler(frame);
			panic("we should never reach this");
		case INT_BREAK:
			while(1) monitor(NULL);
		case IRQ_TIMER:
			// cprintf("timer: cpu=%d\n", this_cpu->cpu_id);
			sched_yield();
			
	default: break;
	}

	/* Unexpected trap: The user process or the kernel has a bug. */
	print_int_frame(frame);

	if (frame->cs == GDT_KCODE) {
		panic("unhandled interrupt in kernel");
	} else {
		task_destroy(cur_task);
		return;
	}
}

void int_handler(struct int_frame *frame)
{
	#ifdef USE_BIG_KERNEL_LOCK
	spin_lock(&kernel_lock);
	#endif
	// cprintf("int_handler, pid=%d\n", cur_task->task_pid);
	UNLOCK_TASK_SWAPPER(cur_task);
	/* The task may have set DF and some versions of GCC rely on DF being
	 * clear. */
	asm volatile("cld" ::: "cc");

	/* Check if interrupts are disabled.
	 * If this assertion fails, DO NOT be tempted to fix it by inserting a
	 * "cli" in the interrupt path.
	 */
	assert(!(read_rflags() & FLAGS_IF));

	// cprintf("Incoming INT frame at %p\n", frame);

	if ((frame->cs & 3) == 3 || cur_task->task_type==TASK_TYPE_KERNEL) {
		/* Interrupt from user mode. */
		assert(cur_task);

		/* Copy interrupt frame (which is currently on the stack) into
		 * 'cur_task->task_frame', so that running the task will restart at
		 * the point of interrupt. */
		cur_task->task_frame = *frame;

		/* Avoid using the frame on the stack. */
		frame = &cur_task->task_frame;
	}

	/* Dispatch based on the type of interrupt that occurred. */
	int_dispatch(frame);

	/* Return to the current task, which should be running. */
	task_run(cur_task);
}

void page_fault_handler(struct int_frame *frame)
{
	void *fault_va;
	unsigned perm = 0;
	int ret;

	/* Read the CR2 register to find the faulting address. */
	fault_va = (void *)read_cr2();
	// cprintf("PAGE FAULT!! cr2=%p, errorCode=%p\n", fault_va, frame->err_code);

	/* Handle kernel-mode page faults. */
	/* LAB 3: your code here. */
	if ((frame->cs & 3) == 0) {
		panic("kernel page fault at rip=%p, faulting address=%p, cpu=%d\n", frame->rip, fault_va, this_cpu->cpu_id);
	}

	/* We have already handled kernel-mode exceptions, so if we get here, the
	 * page fault has happened in user mode.
	 */
	if(task_page_fault_handler(cur_task, fault_va, frame->err_code) == 0){
		task_run(cur_task);
	} else {
		// try to pop frame
		cprintf("Mapping failed\n");
	}

	/* Destroy the task that caused the fault. */
	cprintf("[PID %5u] user fault va %p ip %p\n",
		cur_task->task_pid, fault_va, frame->rip);
	print_int_frame(frame);

	
	

	task_destroy(cur_task);
}

