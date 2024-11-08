#ifndef __UNICORN_EMU_H
#define __UNICORN_EMU_H

struct uc_struct;

struct emu {
	struct uc_struct *uc;
	struct pt_regs *regs;
	struct emu_mm *mm;
	unsigned long tls_ptr;
	unsigned long mm_change_count;
};

struct emu_mm {
	unsigned long change_count;
};

#endif