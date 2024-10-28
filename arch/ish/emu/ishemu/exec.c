#include <linux/sched/signal.h>
#include <asm/pgtable.h>
#include <linux/stdarg.h>

#include "emu/interrupt.h"
#include "emu/cpu.h"

// linker error fixes
int current_pid(void)
{
	return current->pid;
}
void die(const char *message)
{
	panic(message);
}
void ish_printk(const char *msg, ...)
{
	static __thread char log_line[256] = "";
	va_list args;
	va_start(args, msg);
	vsnprintf(log_line + strlen(log_line), sizeof(log_line) - strlen(log_line), msg, args);
	va_end(args);
	if (msg[strlen(msg) - 1] == '\n') {
		printk("%s", log_line);
		log_line[0] = '\0';
	}
}
