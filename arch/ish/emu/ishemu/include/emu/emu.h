#ifndef __ISHEMU_EMU_H
#define __ISHEMU_EMU_H

#include "emu/cpu.h"

struct emu {
	struct cpu_state cpu;
};

struct emu_mm {
	struct mmu mmu;
};

#endif
