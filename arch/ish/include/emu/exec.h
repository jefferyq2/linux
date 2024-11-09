#ifndef __ISH_EXEC_H
#define __ISH_EXEC_H

#include <asm/ptrace.h>

/* Dear future traveler: This is the wrong abstraction, don't feel bad about tearing it apart. */

struct emu {
	struct emu_mm *mm;
	void *ctx;
	void *snapshot;
};

struct emu_mm {
	void *ctx;
	unsigned long flush_count;
};

extern void emu_run(struct emu *emu);
extern void emu_poke_cpu(int cpu);
extern void emu_finish_fork(struct emu *emu);
extern void emu_destroy(struct emu *emu);

extern void emu_mmu_init(struct emu_mm *mm);
extern void emu_mmu_destroy(struct emu_mm *mm);
extern void emu_switch_mm(struct emu *emu, struct emu_mm *mm);
extern void emu_flush_tlb_local(struct emu_mm *mm, unsigned long start, unsigned long end);

#endif