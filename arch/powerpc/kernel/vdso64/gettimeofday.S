/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Userland implementation of gettimeofday() for 64 bits processes in a
 * ppc64 kernel for use in the vDSO
 *
 * Copyright (C) 2004 Benjamin Herrenschmuidt (benh@kernel.crashing.org),
 *                    IBM Corp.
 */
#include <asm/processor.h>
#include <asm/ppc_asm.h>
#include <asm/vdso.h>
#include <asm/vdso_datapage.h>
#include <asm/asm-offsets.h>
#include <asm/unistd.h>

	.text

.macro cvdso_call funct
	mflr	r0
	std	r0, 16(r1)
	stdu	r1, -128(r1)
	get_datapage	r5, VDSO_DATA_OFFSET
	bl	\funct
	addi	r1, r1, 128
	ld	r0, 16(r1)
	cmpwi	r3, 0
	mtlr	r0
	crclr	so
	beqlr+
	crset	so
	neg	r3, r3
	blr
.endm

/*
 * Exact prototype of gettimeofday
 *
 * int __kernel_gettimeofday(struct timeval *tv, struct timezone *tz);
 *
 */
V_FUNCTION_BEGIN(__kernel_gettimeofday)
  .cfi_startproc
	cvdso_call __c_kernel_gettimeofday
  .cfi_endproc
V_FUNCTION_END(__kernel_gettimeofday)


/*
 * Exact prototype of clock_gettime()
 *
 * int __kernel_clock_gettime(clockid_t clock_id, struct timespec *tp);
 *
 */
V_FUNCTION_BEGIN(__kernel_clock_gettime)
  .cfi_startproc
	cvdso_call __c_kernel_clock_gettime
  .cfi_endproc
V_FUNCTION_END(__kernel_clock_gettime)


/*
 * Exact prototype of clock_getres()
 *
 * int __kernel_clock_getres(clockid_t clock_id, struct timespec *res);
 *
 */
V_FUNCTION_BEGIN(__kernel_clock_getres)
  .cfi_startproc
	cvdso_call __c_kernel_clock_getres
  .cfi_endproc
V_FUNCTION_END(__kernel_clock_getres)

/*
 * Exact prototype of time()
 *
 * time_t time(time *t);
 *
 */
V_FUNCTION_BEGIN(__kernel_time)
  .cfi_startproc
	mflr	r0
	std	r0, 16(r1)
	stdu	r1, -128(r1)
	get_datapage	r4, VDSO_DATA_OFFSET
	bl	__c_kernel_time
	addi	r1, r1, 128
	ld	r0, 16(r1)
	crclr	cr0*4+so
	mtlr	r0
	blr
  .cfi_endproc
V_FUNCTION_END(__kernel_time)
