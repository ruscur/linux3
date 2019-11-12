/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _POWERPC_PERF_CALLCHAIN_H
#define _POWERPC_PERF_CALLCHAIN_H

int read_user_stack_slow(void __user *ptr, void *buf, int nb);
void perf_callchain_user_64(struct perf_callchain_entry_ctx *entry,
			    struct pt_regs *regs);
void perf_callchain_user_32(struct perf_callchain_entry_ctx *entry,
			    struct pt_regs *regs);

static inline int valid_user_sp(unsigned long sp, int is_64)
{
	unsigned long stack_top;

	if (IS_ENABLED(CONFIG_PPC32))
		stack_top = STACK_TOP;
	else    /* STACK_TOP uses is_32bit_task() but we want is_64 */
		stack_top = is_64 ? STACK_TOP_USER64 : STACK_TOP_USER32;

	if (!sp || (sp & (is_64 ? 7 : 3)) || sp > stack_top - (is_64 ? 32 : 16))
		return 0;
	return 1;
}

#endif /* _POWERPC_PERF_CALLCHAIN_H */
