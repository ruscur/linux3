/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_VDSO_GETTIMEOFDAY_H
#define __ASM_VDSO_GETTIMEOFDAY_H

#ifndef __ASSEMBLY__

#include <asm/time.h>
#include <asm/unistd.h>
#include <uapi/linux/time.h>

#define VDSO_HAS_CLOCK_GETRES		1

#define VDSO_HAS_TIME			1

#define VDSO_GETS_VD_PTR_FROM_ARCH	1

static __always_inline int do_syscall_2(const unsigned long _r0, const unsigned long _r3,
					const unsigned long _r4)
{
	register long r0 asm("r0") = _r0;
	register unsigned long r3 asm("r3") = _r3;
	register unsigned long r4 asm("r4") = _r4;
	register int ret asm ("r3");

	asm volatile(
		"       sc\n"
		"	bns+	1f\n"
		"	neg	%0, %0\n"
		"1:\n"
	: "+r" (ret), "+r" (r3), "+r" (r4), "+r" (r0)
	:
	: "memory", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "cr0", "ctr");

	return ret;
}

static __always_inline
int gettimeofday_fallback(struct __kernel_old_timeval *_tv, struct timezone *_tz)
{
	return do_syscall_2(__NR_gettimeofday, (unsigned long)_tv, (unsigned long)_tz);
}

static __always_inline
int clock_gettime_fallback(clockid_t _clkid, struct __kernel_timespec *_ts)
{
	return do_syscall_2(__NR_clock_gettime, _clkid, (unsigned long)_ts);
}

static __always_inline
int clock_getres_fallback(clockid_t _clkid, struct __kernel_timespec *_ts)
{
	return do_syscall_2(__NR_clock_getres, _clkid, (unsigned long)_ts);
}

#ifdef CONFIG_VDSO32

#define VDSO_HAS_32BIT_FALLBACK		1

static __always_inline
int clock_gettime32_fallback(clockid_t _clkid, struct old_timespec32 *_ts)
{
	return do_syscall_2(__NR_clock_gettime, _clkid, (unsigned long)_ts);
}

static __always_inline
int clock_getres32_fallback(clockid_t _clkid, struct old_timespec32 *_ts)
{
	return do_syscall_2(__NR_clock_getres, _clkid, (unsigned long)_ts);
}
#endif

static __always_inline u64 __arch_get_hw_counter(s32 clock_mode)
{
	/*
	 * clock_mode == 0 implies that vDSO are enabled otherwise
	 * fallback on syscall.
	 */
	if (clock_mode != 0)
		return U64_MAX;

	return get_tb();
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
static __always_inline u64 vdso_calc_delta(u64 cycles, u64 last, u64 mask, u32 mult)
{
	return (cycles - last) * mult;
}
#define vdso_calc_delta vdso_calc_delta

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_VDSO_GETTIMEOFDAY_H */
