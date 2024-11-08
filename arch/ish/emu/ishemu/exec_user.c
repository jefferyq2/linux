#include <stdlib.h>
#include <asm/ptrace.h>
#include <emu/emu.h>
#include <emu/exec.h>
#include <emu/kernel.h>
#include "../kernel/irq_user.h"

#include "emu/cpu.h"
#include "emu/tlb.h"
#include "emu/interrupt.h"
#define ENGINE_ASBESTOS 1
#include "asbestos/asbestos.h"

extern int current_pid(void);

static __thread struct tlb the_tlb;

static void *ishemu_translate(struct mmu *mem, addr_t addr, int type)
{
	bool writable;
	void *ptr = user_to_kernel_emu(container_of(mem, struct emu_mm, mmu), addr, &writable);
	if (ptr && type == MEM_WRITE && !writable) {
		ptr = NULL;
	}
	return ptr;
}

static struct mmu_ops ishemu_ops = {
	.translate = ishemu_translate,
};

extern unsigned long (*sys_call_table[])(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

static bool poke[NR_CPUS];

static void emu_run_to_interrupt(struct emu *emu, struct pt_regs *regs)
{
	emu->cpu.eax = regs->ax;
	emu->cpu.ebx = regs->bx;
	emu->cpu.ecx = regs->cx;
	emu->cpu.edx = regs->dx;
	emu->cpu.esi = regs->si;
	emu->cpu.edi = regs->di;
	emu->cpu.ebp = regs->bp;
	emu->cpu.esp = regs->sp;
	emu->cpu.eip = regs->ip;
	emu->cpu.eflags = regs->flags;
	emu->cpu.tls_ptr = regs->tls;
	expand_flags(&emu->cpu);
	emu->cpu.poked_ptr = &poke[get_smp_processor_id()];

	int interrupt = cpu_run_to_interrupt(&emu->cpu, &the_tlb);

	collapse_flags(&emu->cpu);
	regs->ax = emu->cpu.eax;
	regs->bx = emu->cpu.ebx;
	regs->cx = emu->cpu.ecx;
	regs->dx = emu->cpu.edx;
	regs->si = emu->cpu.esi;
	regs->di = emu->cpu.edi;
	regs->bp = emu->cpu.ebp;
	regs->sp = emu->cpu.esp;
	regs->ip = emu->cpu.eip;
	regs->flags = emu->cpu.eflags;
	regs->tls = emu->cpu.tls_ptr;

	if (interrupt == INT_GPF) {
		regs->cr2 = emu->cpu.segfault_addr;
		regs->error_code = emu->cpu.segfault_was_write << 1;
	} else {
		regs->cr2 = regs->error_code = 0;
	}
	regs->trap_nr = interrupt;
}

void emu_run(struct emu *emu, struct pt_regs *regs)
{
	for (;;) {
		emu_run_to_interrupt(emu, regs);
		handle_cpu_trap();
	}
}

void emu_finish_fork(struct emu *emu, struct emu *next)
{
}

void emu_destroy(struct emu *emu)
{
}

void emu_poke_cpu(int cpu)
{
	__atomic_store_n(&poke[cpu], true, __ATOMIC_SEQ_CST);
}

void emu_flush_tlb_local(struct emu_mm *mm, unsigned long start, unsigned long end)
{
	if (the_tlb.mmu == NULL)
		return;
	tlb_flush(&the_tlb);
	if (mm->mmu.asbestos != NULL)
		asbestos_invalidate_range(mm->mmu.asbestos, start / PAGE_SIZE, (end + PAGE_SIZE - 1) / PAGE_SIZE /* TODO DIV_ROUND_UP? */);
}

void emu_mmu_init(struct emu_mm *mm)
{
	mm->mmu.asbestos = asbestos_new(&mm->mmu);
	mm->mmu.ops = &ishemu_ops;
}

void emu_mmu_destroy(struct emu_mm *mm)
{
	asbestos_free(mm->mmu.asbestos);
	mm->mmu.asbestos = NULL;
}

void emu_switch_mm(struct emu *emu, struct emu_mm *mm) {
	if (mm->mmu.asbestos == NULL)
		emu_mmu_init( mm);
	emu->cpu.mmu = &mm->mmu;
	tlb_refresh(&the_tlb, &mm->mmu);
}
