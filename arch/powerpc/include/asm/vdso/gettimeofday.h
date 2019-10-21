/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 ARM Limited
 */
#ifndef __ASM_VDSO_GETTIMEOFDAY_H
#define __ASM_VDSO_GETTIMEOFDAY_H

#ifndef __ASSEMBLY__

#include <asm/time.h>
#include <asm/unistd.h>
#include <uapi/linux/time.h>

#define __VDSO_USE_SYSCALL		ULLONG_MAX

#define VDSO_HAS_CLOCK_GETRES		1

#define VDSO_HAS_TIME			1

#define VDSO_HAS_32BIT_FALLBACK		1

static __always_inline
int gettimeofday_fallback(struct __kernel_old_timeval *_tv,
			  struct timezone *_tz)
{
	return -1;
}

static __always_inline
long clock_gettime_fallback(clockid_t _clkid, struct __kernel_timespec *_ts)
{
	return -1;
}

static __always_inline
int clock_getres_fallback(clockid_t _clkid, struct __kernel_timespec *_ts)
{
	return -1;
}

static __always_inline
int clock_getres32_fallback(clockid_t clock, struct old_timespec32 *res)
{
	return -1;
}

static __always_inline
int clock_gettime32_fallback(clockid_t clock, struct old_timespec32 *res)
{
	return -1;
}

static __always_inline u64 __arch_get_hw_counter(s32 clock_mode)
{
	/*
	 * clock_mode == 0 implies that vDSO are enabled otherwise
	 * fallback on syscall.
	 */
	if (clock_mode)
		return __VDSO_USE_SYSCALL;

	return get_tb();
}

static __always_inline
const struct vdso_data *__arch_get_vdso_data(void)
{
	void *ptr;

	asm volatile(
		"	bcl	20, 31, .+4;\n"
		"	mflr	%0;\n"
		"	addi	%0, %0, __kernel_datapage_offset - (.-4);\n"
		: "=b"(ptr) : : "lr");

	return ptr + *(unsigned long *)ptr;
}

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_VDSO_GETTIMEOFDAY_H */
