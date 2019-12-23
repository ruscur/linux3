/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_VDSO_GETTIMEOFDAY_H
#define __ASM_VDSO_GETTIMEOFDAY_H

#ifndef __ASSEMBLY__

#include <asm/time.h>
#include <asm/unistd.h>
#include <uapi/linux/time.h>

#define VDSO_HAS_CLOCK_GETRES		1

#define VDSO_HAS_TIME			1

static __always_inline u64 __arch_get_hw_counter(s32 clock_mode)
{
	/*
	 * clock_mode == 0 implies that vDSO are enabled otherwise
	 * fallback on syscall.
	 */
	if (clock_mode)
		return ULLONG_MAX;

	return get_tb() & LLONG_MAX;
}

/*
 * powerpc specific delta calculation.
 *
 * This variant removes the masking of the subtraction because the
 * clocksource mask of all VDSO capable clocksources on powerpc is U64_MAX
 * which would result in a pointless operation. The compiler cannot
 * optimize it away as the mask comes from the vdso data and is not compile
 * time constant.
 */
static __always_inline
u64 vdso_calc_delta(u64 cycles, u64 last, u64 mask, u32 mult)
{
	return (cycles - last) * mult;
}
#define vdso_calc_delta vdso_calc_delta

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_VDSO_GETTIMEOFDAY_H */
