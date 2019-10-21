// SPDX-License-Identifier: GPL-2.0
/*
 * ARM64 userspace implementations of gettimeofday() and similar.
 *
 * Copyright (C) 2018 ARM Limited
 *
 */
#include <linux/time.h>
#include <linux/types.h>

int __c_kernel_clock_gettime(clockid_t clock,
			   struct old_timespec32 *ts)
{
	return __cvdso_clock_gettime32(clock, ts);
}

int __c_kernel_gettimeofday(struct __kernel_old_timeval *tv,
			  struct timezone *tz)
{
	return __cvdso_gettimeofday(tv, tz);
}

int __c_kernel_clock_getres(clockid_t clock_id,
			  struct old_timespec32 *res)
{
	return __cvdso_clock_getres_time32(clock_id, res);
}

time_t __c_kernel_time(time_t *time)
{
	return __cvdso_time(time);
}
