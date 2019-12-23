// SPDX-License-Identifier: GPL-2.0
/*
 * ARM64 userspace implementations of gettimeofday() and similar.
 *
 * Copyright (C) 2018 ARM Limited
 *
 */
#include <linux/time.h>
#include <linux/types.h>

int __c_kernel_clock_gettime(clockid_t clock, struct old_timespec32 *ts,
			     const struct vdso_data *vd)
{
	return __cvdso_clock_gettime32(vd, clock, ts);
}

int __c_kernel_gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz,
			    const struct vdso_data *vd)
{
	return __cvdso_gettimeofday(vd, tv, tz);
}

int __c_kernel_clock_getres(clockid_t clock_id, struct old_timespec32 *res,
			    const struct vdso_data *vd)
{
	return __cvdso_clock_getres_time32(vd, clock_id, res);
}

time_t __c_kernel_time(time_t *time, const struct vdso_data *vd)
{
	return __cvdso_time(vd, time);
}
