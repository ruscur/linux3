// SPDX-License-Identifier: GPL-2.0-only
/*
 * ARM userspace implementations of gettimeofday() and similar.
 *
 * Copyright 2015 Mentor Graphics Corporation.
 */
#include <linux/time.h>
#include <linux/types.h>

int __vdso_clock_gettime(clockid_t clock,
			 struct old_timespec32 *ts)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret = __cvdso_clock_gettime32(vd, clock, ts);

	if (likely(!ret))
		return ret;

	return clock_gettime32_fallback(clock, &ts);
}

int __vdso_clock_gettime64(clockid_t clock,
			   struct __kernel_timespec *ts)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret = __cvdso_clock_gettime(vd, clock, ts);

	if (likely(!ret))
		return ret;

	return clock_gettime_fallback(clock, ts);
}

int __vdso_gettimeofday(struct __kernel_old_timeval *tv,
			struct timezone *tz)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret = __cvdso_gettimeofday(vd, tv, tz);

	if (likely(!ret))
		return ret;

	return gettimeofday_fallback(tv, tz);
}

int __vdso_clock_getres(clockid_t clock_id,
			struct old_timespec32 *res)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret = __cvdso_clock_getres_time32(vd, clock_id, res);

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
