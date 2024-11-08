#ifndef __ASM_ISH_MMU_CONTEXT_H
#define __ASM_ISH_MMU_CONTEXT_H

#include <asm-generic/mm_hooks.h>
#include <emu/exec.h>

/* Dear future traveller: This is the wrong abstraction, don't feel bad about tearing it apart. */

static inline void enter_lazy_tlb(struct mm_struct *mm,
			struct task_struct *tsk)
{
}

static inline int init_new_context(struct task_struct *tsk,
			struct mm_struct *mm)
{
	emu_mmu_init(&mm->context.emu_mm);
	return 0;
}

static inline void destroy_context(struct mm_struct *mm)
{
	emu_mmu_destroy(&mm->context.emu_mm);
}

static inline void deactivate_mm(struct task_struct *task,
				 struct mm_struct *mm)
{
}

static inline void switch_mm(struct mm_struct *prev,
			struct mm_struct *next,
			struct task_struct *tsk)
{
	int cpu = smp_processor_id();
	BUG_ON(next != tsk->mm);
	if (next != NULL) {
		emu_switch_mm(&tsk->thread.emu, next ? &next->context.emu_mm : NULL);
	}
	cpumask_clear_cpu(cpu, mm_cpumask(prev));
	cpumask_set_cpu(cpu, mm_cpumask(next));
}

static inline void activate_mm(struct mm_struct *prev_mm,
			       struct mm_struct *next_mm)
{
	switch_mm(prev_mm, next_mm, current);
}

#endif
