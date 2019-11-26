/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _POWERPC_PERF_CALLCHAIN_H
#define _POWERPC_PERF_CALLCHAIN_H

int read_user_stack_slow(void __user *ptr, void *buf, int nb);
void perf_callchain_user_64(struct perf_callchain_entry_ctx *entry,
			    struct pt_regs *regs);
void perf_callchain_user_32(struct perf_callchain_entry_ctx *entry,
			    struct pt_regs *regs);

static inline int valid_user_sp(unsigned long sp)
{
	bool is_64 = !is_32bit_task();

	if (!sp || (sp & (is_64 ? 7 : 3)) || sp > STACK_TOP - (is_64 ? 32 : 16))
		return 0;
	return 1;
}

#endif /* _POWERPC_PERF_CALLCHAIN_H */
