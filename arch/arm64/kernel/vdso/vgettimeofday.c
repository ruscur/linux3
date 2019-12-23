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
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret = __cvdso_clock_gettime(vd, clock, ts);

	if (likely(!ret))
		return ret;

	return clock_gettime_fallback(clock, ts);
}

int __kernel_gettimeofday(struct __kernel_old_timeval *tv,
			  struct timezone *tz)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret = __cvdso_gettimeofday(vd, tv, tz);

	if (likely(!ret))
		return ret;

	return gettimeofday_fallback(tv, tz);
}

int __kernel_clock_getres(clockid_t clock_id,
			  struct __kernel_timespec *res)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret =  __cvdso_clock_getres(vd, clock_id, res);

	if (likely(!ret))
		return ret;

	return clock_getres_fallback(clock, res);
}
