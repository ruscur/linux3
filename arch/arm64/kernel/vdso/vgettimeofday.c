// SPDX-License-Identifier: GPL-2.0
/*
 * ARM64 userspace implementations of gettimeofday() and similar.
 *
 * Copyright (C) 2018 ARM Limited
 *
 */
#include <linux/time.h>
#include <linux/types.h>

int __kernel_clock_gettime(clockid_t clock,
			   struct __kernel_timespec *ts)
{
	int ret = __cvdso_clock_gettime(clock, ts);

	if (likely(!ret))
		return ret;

	return clock_gettime_fallback(clock, ts);
}

int __kernel_gettimeofday(struct __kernel_old_timeval *tv,
			  struct timezone *tz)
{
	int ret = __cvdso_gettimeofday(tv, tz);

	if (likely(!ret))
		return ret;

	return gettimeofday_fallback(tv, tz);
}

int __kernel_clock_getres(clockid_t clock_id,
			  struct __kernel_timespec *res)
{
	int ret =  __cvdso_clock_getres(clock_id, res);

	if (likely(!ret))
		return ret;

	return clock_getres_fallback(clock, res);
}
