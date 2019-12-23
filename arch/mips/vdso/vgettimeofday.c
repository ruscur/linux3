// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MIPS64 and compat userspace implementations of gettimeofday()
 * and similar.
 *
 * Copyright (C) 2015 Imagination Technologies
 * Copyright (C) 2018 ARM Limited
 *
 */
#include <linux/time.h>
#include <linux/types.h>

#if _MIPS_SIM != _MIPS_SIM_ABI64
int __vdso_clock_gettime(clockid_t clock,
			 struct old_timespec32 *ts)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret = __cvdso_clock_gettime32(vd, clock, ts);

	if (likely(!ret))
		return ret;

	return clock_gettime32_fallback(clock, ts);
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

int __vdso_clock_gettime64(clockid_t clock,
			   struct __kernel_timespec *ts)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret = __cvdso_clock_gettime(vd, clock, ts);

	if (likely(!ret))
		return ret;

	return clock_gettime_fallback(clock, ts);
}

#else

int __vdso_clock_gettime(clockid_t clock,
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
			struct __kernel_timespec *res)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	int ret =  __cvdso_clock_getres(vd, clock_id, res);

	if (likely(!ret))
		return ret;

	return clock_getres_fallback(clock, res);
}

#endif
