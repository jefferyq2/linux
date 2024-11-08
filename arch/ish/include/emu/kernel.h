#ifndef __ISH_EMU_KERNEL_H
#define __ISH_EMU_KERNEL_H

struct emu_mm;

/* kernel functions for emulators to call */
extern void handle_cpu_trap(void);
extern void *user_to_kernel_emu(struct emu_mm *emu_mm, unsigned long virt, bool *writable);

#endif
