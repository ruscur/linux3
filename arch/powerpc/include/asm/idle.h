#ifndef _ASM_POWERPC_IDLE_H
#define _ASM_POWERPC_IDLE_H
#include <asm/runlatch.h>

static inline void idle_loop_prolog(unsigned long *in_purr)
{
	ppc64_runlatch_off();
	*in_purr = mfspr(SPRN_PURR);
	/*
	 * Indicate to the HV that we are idle. Now would be
	 * a good time to find other work to dispatch.
	 */
	get_lppaca()->idle = 1;
}

static inline void idle_loop_epilog(unsigned long in_purr)
{
	u64 wait_cycles;

	wait_cycles = be64_to_cpu(get_lppaca()->wait_state_cycles);
	wait_cycles += mfspr(SPRN_PURR) - in_purr;
	get_lppaca()->wait_state_cycles = cpu_to_be64(wait_cycles);
	get_lppaca()->idle = 0;

	ppc64_runlatch_on();
}
#endif
