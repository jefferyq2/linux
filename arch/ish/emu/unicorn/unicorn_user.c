#include <unicorn/unicorn.h>
#include <asm/ptrace.h>
#include <asm/page.h>

#include "unicorn.h"

#include <emu/exec.h>
#include <emu/kernel.h>
#include <emu/emu.h>

#define check(err) __check(err, __FUNCTION__, __LINE__)
static void __check(uc_err err, const char *function, int line)
{
	if (err != UC_ERR_OK) {
		panic("%s:%d: %s", function, line, uc_strerror(err));
	}
}

#define uc_reg(op, uc, reg_id, field) \
	check(uc_reg_##op##2((uc), (reg_id), (field), (size_t[]){sizeof(*(field))}))

//////////////////////

struct gdt_desc {
	unsigned limit1:16;
	unsigned base1:16;
	unsigned base2:8;
	unsigned type:4;
	unsigned system:1;
	unsigned dpl:2;
	unsigned present:1;
	unsigned limit2:4;
	unsigned avl:1;
	unsigned _:1;
	unsigned db:1;
	unsigned granularity:1;
	unsigned base3:8;
} __attribute__((packed));

static const uint32_t gdt_base = 0xfffff000;
static const uint32_t gdt_size = 16 * sizeof(struct gdt_desc);

static void install_gdt_segment(uc_engine *uc, int segment, uint32_t base, int dpl)
{
	struct gdt_desc desc = {
		.limit1 = 0xffff,
		.limit2 = 0xf,
		.base1 = (base & 0x0000ffff) >> 0,
		.base2 = (base & 0x00ff0000) >> 16,
		.base3 = (base & 0xff000000) >> 24,
		.type = 3, // read & write
		.system = 1, // user
		.dpl = dpl,
		.present = 1,
		.db = 1, // 32 bit code
		.granularity = 1,
	};
	check(uc_mem_write(uc, gdt_base + (segment * sizeof(desc)), &desc, sizeof(desc)));
}

///////////////////

static void load_regs(struct emu *emu)
{
	uc_engine *uc = emu->uc;
	struct pt_regs *regs = emu->regs;
	uc_reg(write, uc, UC_X86_REG_EAX, &regs->ax);
	uc_reg(write, uc, UC_X86_REG_EBX, &regs->bx);
	uc_reg(write, uc, UC_X86_REG_ECX, &regs->cx);
	uc_reg(write, uc, UC_X86_REG_EDX, &regs->dx);
	uc_reg(write, uc, UC_X86_REG_ESI, &regs->si);
	uc_reg(write, uc, UC_X86_REG_EDI, &regs->di);
	uc_reg(write, uc, UC_X86_REG_EBP, &regs->bp);
	uc_reg(write, uc, UC_X86_REG_ESP, &regs->sp);
	uc_reg(write, uc, UC_X86_REG_EIP, &regs->ip);
	uc_reg(write, uc, UC_X86_REG_FLAGS, &regs->flags);

	if (emu->tls_ptr != regs->tls) {
		emu->tls_ptr = regs->tls;
		install_gdt_segment(uc, 0xc, emu->tls_ptr, 3);
	}
	unsigned long mm_change_count = __atomic_load_n(&emu->mm->change_count, __ATOMIC_SEQ_CST);
	if (emu->mm_change_count != mm_change_count) {
		check(uc_ctl_flush_tlb(uc));
		emu->mm_change_count = mm_change_count;
	}
}

static void save_regs(struct emu *emu)
{
	uc_engine *uc = emu->uc;
	struct pt_regs *regs = emu->regs;
	regs->ax = 0;
	uc_reg(read, uc, UC_X86_REG_EAX, &regs->ax);
	uc_reg(read, uc, UC_X86_REG_EBX, &regs->bx);
	uc_reg(read, uc, UC_X86_REG_ECX, &regs->cx);
	uc_reg(read, uc, UC_X86_REG_EDX, &regs->dx);
	uc_reg(read, uc, UC_X86_REG_ESI, &regs->si);
	uc_reg(read, uc, UC_X86_REG_EDI, &regs->di);
	uc_reg(read, uc, UC_X86_REG_EBP, &regs->bp);
	uc_reg(read, uc, UC_X86_REG_ESP, &regs->sp);
	uc_reg(read, uc, UC_X86_REG_EIP, &regs->ip);
	uc_reg(read, uc, UC_X86_REG_FLAGS, &regs->flags);
}

static void do_trap(struct emu *emu, int trap_nr)
{
	save_regs(emu);
	emu->regs->trap_nr = trap_nr;
	handle_cpu_trap();
	load_regs(emu);
}

////////////////

static bool mem_type_is_write(uc_mem_type type)
{
	switch (type) {
	case UC_MEM_READ:
	case UC_MEM_READ_UNMAPPED:
	case UC_MEM_READ_PROT:
	case UC_MEM_READ_AFTER:
	case UC_MEM_FETCH:
	case UC_MEM_FETCH_UNMAPPED:
	case UC_MEM_FETCH_PROT:
		return false;
	case UC_MEM_WRITE:
	case UC_MEM_WRITE_UNMAPPED:
	case UC_MEM_WRITE_PROT:
		return true;
	}
}

static bool hook_tlb_fill(uc_engine *uc, uint64_t vaddr, uc_mem_type type, uc_tlb_entry *result, void *user_data)
{
	struct emu *emu = user_data;

	if (vaddr == gdt_base) {
		result->paddr = vaddr;
		result->perms = UC_PROT_READ | UC_PROT_WRITE;
		return true;
	}

	bool is_write = mem_type_is_write(type);
	bool writable;
	void *kernel_addr = user_to_kernel_emu(emu->mm, vaddr, &writable);

	if (kernel_addr == NULL || (is_write && !writable)) {
		emu->regs->cr2 = vaddr;
		emu->regs->error_code = mem_type_is_write(type) ? 2 : 0;
		do_trap(emu, 13);
		kernel_addr = user_to_kernel_emu(emu->mm, vaddr, &writable);
	}
	if (kernel_addr == NULL) {
		uc_emu_stop(uc);
		return false;
	}

	unsigned long paddr = __pa(kernel_addr);
	result->paddr = __pa(kernel_addr);
	result->perms = UC_PROT_READ | UC_PROT_EXEC | (writable ? UC_PROT_WRITE : 0);
	return true;
}

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
	struct emu *emu = user_data;
	do_trap(emu, intno);
}

static bool hook_trace_code(uc_engine *uc, uint64_t address, size_t size, void *user_data)
{
	struct emu *emu = user_data;
	void *ptr = user_to_kernel_emu(emu->mm, address, NULL);
	uint32_t sp;
	uc_reg(read, uc, UC_X86_REG_ESP, &sp);
	extern int current_pid();
	printk("%d code %#llx+%ld %*ph\n", current_pid(), address, size, (int) size, ptr);
	return true;
}

/////////////

static void create_unicorn(struct emu *emu)
{
	uc_hook hh;
	check(uc_open(UC_ARCH_X86, UC_MODE_32, &emu->uc));

	check(uc_mem_map_ptr(emu->uc, 0x0, ish_phys_size, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, (void *) ish_phys_base));
	check(uc_ctl_tlb_mode(emu->uc, UC_TLB_VIRTUAL));
	check(uc_hook_add(emu->uc, &hh, UC_HOOK_TLB_FILL, hook_tlb_fill, emu, 1, 0));

	check(uc_mem_map(emu->uc, gdt_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
	struct uc_x86_mmr gdtr = {.base = gdt_base, .limit = gdt_size};
	uc_reg(write, emu->uc, UC_X86_REG_GDTR, &gdtr);
	// unicorn bug (maybe): if you load any segment register other than ss, sp suddenly becomes 16 bit. can be fixed by loading ss correctly
	install_gdt_segment(emu->uc, 1, 0, 0);
	int seg = (1 << 3) | 0; // ring 0? why?
	uc_reg(write, emu->uc, UC_X86_REG_SS, &seg);

	check(uc_hook_add(emu->uc, &hh, UC_HOOK_INTR, hook_intr, emu, 1, 0));

	if (unicorn_trace) {
		check(uc_hook_add(emu->uc, &hh, UC_HOOK_BLOCK, hook_trace_code, emu, 1, 0));
	}
}

void emu_run(struct emu *emu, struct pt_regs *regs)
{
	if (!emu->uc) {
		create_unicorn(emu);
	}

	emu->regs = regs;

	load_regs(emu);

	for (;;) {
		check(uc_emu_start(emu->uc, regs->ip, 0, 0, 0));
	}
}

void emu_finish_fork(struct emu *emu, struct emu *next)
{
	if (emu->uc == NULL) {
		return;
	}

	create_unicorn(next);

	uint8_t gdt_buf[gdt_size];
	check(uc_mem_read(emu->uc, gdt_base, gdt_buf, gdt_size));
	check(uc_mem_write(next->uc, gdt_base, gdt_buf, gdt_size));

	uc_context *ctx;
	check(uc_context_alloc(emu->uc, &ctx));
	check(uc_context_save(emu->uc, ctx));
	check(uc_context_restore(next->uc, ctx));
	check(uc_context_free(ctx));
}

void emu_destroy(struct emu *emu)
{
	check(uc_close(emu->uc));
	emu->uc = NULL;
}

void emu_poke_cpu(int cpu) {}

void emu_mmu_init(struct emu_mm *mm)
{
}
void emu_mmu_destroy(struct emu_mm *mm)
{
}
void emu_switch_mm(struct emu *emu, struct emu_mm *mm)
{
	emu->mm = mm;
}
void emu_flush_tlb_local(struct emu_mm *mm, unsigned long start, unsigned long end)
{
	__atomic_fetch_add(&mm->change_count, 1, __ATOMIC_SEQ_CST);
}
