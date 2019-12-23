// SPDX-License-Identifier: GPL-2.0
/*
 * ARM64 compat userspace implementations of gettimeofday() and similar.
 *
 * Copyright (C) 2018 ARM Limited
 *
 */
#include <linux/time.h>
#include <linux/types.h>

int __vdso_clock_gettime(clockid_t clock,
			 struct old_timespec32 *ts)
{
	int ret;

	/* The checks below are required for ABI consistency with arm */
	if ((u32)ts >= TASK_SIZE_32)
		return -EFAULT;

	ret = __cvdso_clock_gettime32(clock, ts);

	if (likely(!ret))
		return ret;

	return clock_gettime32_fallback(clock, &ts);
}

int __vdso_clock_gettime64(clockid_t clock,
			   struct __kernel_timespec *ts)
{
	int ret;

	/* The checks below are required for ABI consistency with arm */
	if ((u32)ts >= TASK_SIZE_32)
		return -EFAULT;

	ret = __cvdso_clock_gettime(clock, ts);

	if (likely(!ret))
		return ret;

	return clock_gettime_fallback(clock, ts);
}

int __vdso_gettimeofday(struct __kernel_old_timeval *tv,
			struct timezone *tz)
{
	int ret = __cvdso_gettimeofday(tv, tz);

	if (likely(!ret))
		return ret;

	return gettimeofday_fallback(tv, tz);
}

int __vdso_clock_getres(clockid_t clock_id,
			struct old_timespec32 *res)
{
	int ret;
	struct __kernel_timespec ts;

	/* The checks below are required for ABI consistency with arm */
	if ((u32)res >= TASK_SIZE_32)
		return -EFAULT;

	ret = __cvdso_clock_getres_time32(clock_id, res);

	if (likely(!ret))
		return ret;

	return clock_getres32_fallback(clock, res);
}

/* Avoid unresolved references emitted by GCC */

void __aeabi_unwind_cpp_pr0(void)
{
}

void __aeabi_unwind_cpp_pr1(void)
{
}

void __aeabi_unwind_cpp_pr2(void)
{
}
