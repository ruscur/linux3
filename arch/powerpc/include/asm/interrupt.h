/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_POWERPC_INTERRUPT_H
#define _ASM_POWERPC_INTERRUPT_H

#include <linux/context_tracking.h>
#include <linux/hardirq.h>
#include <asm/cputime.h>
#include <asm/ftrace.h>

#ifdef CONFIG_PPC_BOOK3S_64
static inline void interrupt_enter_prepare(struct pt_regs *regs)
{
	if (irq_soft_mask_set_return(IRQS_ALL_DISABLED) == IRQS_ENABLED)
		trace_hardirqs_off();
	local_paca->irq_happened |= PACA_IRQ_HARD_DIS;

	if (user_mode(regs)) {
		CT_WARN_ON(ct_state() == CONTEXT_KERNEL);
		user_exit_irqoff();

		account_cpu_user_entry();
		account_stolen_time();
	} else {
		CT_WARN_ON(ct_state() == CONTEXT_USER);
	}
}

#else /* CONFIG_PPC_BOOK3S_64 */
static inline void interrupt_enter_prepare(struct pt_regs *regs)
{
}
#endif /* CONFIG_PPC_BOOK3S_64 */

struct interrupt_nmi_state {
#ifdef CONFIG_PPC64
#ifdef CONFIG_PPC_BOOK3S_64
	u8 irq_soft_mask;
	u8 irq_happened;
#endif
	u8 ftrace_enabled;
#endif
};

static inline void interrupt_nmi_enter_prepare(struct pt_regs *regs, struct interrupt_nmi_state *state)
{
#ifdef CONFIG_PPC_BOOK3S_64
	state->irq_soft_mask = local_paca->irq_soft_mask;
	state->irq_happened = local_paca->irq_happened;
	state->ftrace_enabled = this_cpu_get_ftrace_enabled();

	/*
	 * Set IRQS_ALL_DISABLED unconditionally so irqs_disabled() does
	 * the right thing, and set IRQ_HARD_DIS. We do not want to reconcile
	 * because that goes through irq tracing which we don't want in NMI.
	 */
	local_paca->irq_soft_mask = IRQS_ALL_DISABLED;
	local_paca->irq_happened |= PACA_IRQ_HARD_DIS;
#endif

	this_cpu_set_ftrace_enabled(0);

	nmi_enter();
}

static inline void interrupt_nmi_exit_prepare(struct pt_regs *regs, struct interrupt_nmi_state *state)
{
	nmi_exit();

	this_cpu_set_ftrace_enabled(state->ftrace_enabled);

#ifdef CONFIG_PPC_BOOK3S_64
	/* Check we didn't change the pending interrupt mask. */
	WARN_ON_ONCE((state->irq_happened | PACA_IRQ_HARD_DIS) != local_paca->irq_happened);
	local_paca->irq_happened = state->irq_happened;
	local_paca->irq_soft_mask = state->irq_soft_mask;
#endif
}


/**
 * DECLARE_INTERRUPT_HANDLER_RAW - Declare raw interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 */
#define DECLARE_INTERRUPT_HANDLER_RAW(func)				\
	__visible long func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER_RAW - Define raw interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 *
 * @func is called from ASM entry code.
 *
 * This is a plain function which does no tracing, reconciling, etc.
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER_RAW(func)				\
static __always_inline long ___##func(struct pt_regs *regs);		\
									\
__visible noinstr long func(struct pt_regs *regs)			\
{									\
	long ret;							\
									\
	ret = ___##func (regs);						\
									\
	return ret;							\
}									\
									\
static __always_inline long ___##func(struct pt_regs *regs)

/**
 * DECLARE_INTERRUPT_HANDLER - Declare synchronous interrupt handler function
 * @func:	Function name of the entry point
 */
#define DECLARE_INTERRUPT_HANDLER(func)					\
	__visible void func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER - Define synchronous interrupt handler function
 * @func:	Function name of the entry point
 *
 * @func is called from ASM entry code.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER(func)					\
static __always_inline void ___##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	interrupt_enter_prepare(regs);					\
									\
	___##func (regs);						\
}									\
									\
static __always_inline void ___##func(struct pt_regs *regs)

/**
 * DECLARE_INTERRUPT_HANDLER_RET - Declare synchronous interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 */
#define DECLARE_INTERRUPT_HANDLER_RET(func)				\
	__visible long func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER_RET - Define synchronous interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 *
 * @func is called from ASM entry code.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER_RET(func)				\
static __always_inline long ___##func(struct pt_regs *regs);		\
									\
__visible noinstr long func(struct pt_regs *regs)			\
{									\
	long ret;							\
									\
	interrupt_enter_prepare(regs);					\
									\
	ret = ___##func (regs);						\
									\
	return ret;							\
}									\
									\
static __always_inline long ___##func(struct pt_regs *regs)

/**
 * DECLARE_INTERRUPT_HANDLER_ASYNC - Declare asynchronous interrupt handler function
 * @func:	Function name of the entry point
 */
#define DECLARE_INTERRUPT_HANDLER_ASYNC(func)				\
	__visible void func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER_ASYNC - Define asynchronous interrupt handler function
 * @func:	Function name of the entry point
 *
 * @func is called from ASM entry code.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER_ASYNC(func)				\
static __always_inline void ___##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	interrupt_enter_prepare(regs);					\
									\
	___##func (regs);						\
}									\
									\
static __always_inline void ___##func(struct pt_regs *regs)

/**
 * DECLARE_INTERRUPT_HANDLER_NMI - Declare NMI interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 */
#define DECLARE_INTERRUPT_HANDLER_NMI(func)				\
	__visible long func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER_NMI - Define NMI interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 *
 * @func is called from ASM entry code.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER_NMI(func)				\
static __always_inline long ___##func(struct pt_regs *regs);		\
									\
__visible noinstr long func(struct pt_regs *regs)			\
{									\
	struct interrupt_nmi_state state;				\
	long ret;							\
									\
	interrupt_nmi_enter_prepare(regs, &state);			\
									\
	ret = ___##func (regs);						\
									\
	interrupt_nmi_exit_prepare(regs, &state);			\
									\
	return ret;							\
}									\
									\
static __always_inline long ___##func(struct pt_regs *regs)


/* Interrupt handlers */
DECLARE_INTERRUPT_HANDLER_NMI(machine_check_early);
DECLARE_INTERRUPT_HANDLER_NMI(hmi_exception_realmode);
DECLARE_INTERRUPT_HANDLER(SMIException);
DECLARE_INTERRUPT_HANDLER(handle_hmi_exception);
DECLARE_INTERRUPT_HANDLER(instruction_breakpoint_exception);
DECLARE_INTERRUPT_HANDLER(RunModeException);
DECLARE_INTERRUPT_HANDLER(single_step_exception);
DECLARE_INTERRUPT_HANDLER(program_check_exception);
DECLARE_INTERRUPT_HANDLER(alignment_exception);
DECLARE_INTERRUPT_HANDLER(StackOverflow);
DECLARE_INTERRUPT_HANDLER(kernel_fp_unavailable_exception);
DECLARE_INTERRUPT_HANDLER(altivec_unavailable_exception);
DECLARE_INTERRUPT_HANDLER(vsx_unavailable_exception);
DECLARE_INTERRUPT_HANDLER(fp_unavailable_tm);
DECLARE_INTERRUPT_HANDLER(altivec_unavailable_tm);
DECLARE_INTERRUPT_HANDLER(vsx_unavailable_tm);
DECLARE_INTERRUPT_HANDLER(facility_unavailable_exception);
DECLARE_INTERRUPT_HANDLER(TAUException);
DECLARE_INTERRUPT_HANDLER(altivec_assist_exception);
DECLARE_INTERRUPT_HANDLER(unrecoverable_exception);
DECLARE_INTERRUPT_HANDLER(kernel_bad_stack);
DECLARE_INTERRUPT_HANDLER_NMI(system_reset_exception);
#ifdef CONFIG_PPC_BOOK3S_64
DECLARE_INTERRUPT_HANDLER_ASYNC(machine_check_exception);
#else
DECLARE_INTERRUPT_HANDLER_NMI(machine_check_exception);
#endif
DECLARE_INTERRUPT_HANDLER(emulation_assist_interrupt);
DECLARE_INTERRUPT_HANDLER_RAW(do_slb_fault);
DECLARE_INTERRUPT_HANDLER(do_bad_slb_fault);
DECLARE_INTERRUPT_HANDLER_RET(do_page_fault);
DECLARE_INTERRUPT_HANDLER(do_bad_page_fault);

DECLARE_INTERRUPT_HANDLER_ASYNC(timer_interrupt);
DECLARE_INTERRUPT_HANDLER_ASYNC(performance_monitor_exception);
DECLARE_INTERRUPT_HANDLER(WatchdogException);
DECLARE_INTERRUPT_HANDLER(unknown_exception);
DECLARE_INTERRUPT_HANDLER_ASYNC(unknown_async_exception);

void replay_system_reset(void);
void replay_soft_interrupts(void);

static inline void interrupt_cond_local_irq_enable(struct pt_regs *regs)
{
	if (!arch_irq_disabled_regs(regs))
		local_irq_enable();
}

#endif /* _ASM_POWERPC_INTERRUPT_H */
