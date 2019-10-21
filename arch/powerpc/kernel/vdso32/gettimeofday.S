/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Userland implementation of gettimeofday() for 32 bits processes in a
 * ppc64 kernel for use in the vDSO
 *
 * Copyright (C) 2004 Benjamin Herrenschmuidt (benh@kernel.crashing.org,
 *                    IBM Corp.
 */
#include <asm/processor.h>
#include <asm/ppc_asm.h>
#include <asm/vdso.h>
#include <asm/asm-offsets.h>
#include <asm/unistd.h>

	.text
/*
 * Exact prototype of gettimeofday
 *
 * int __kernel_gettimeofday(struct timeval *tv, struct timezone *tz);
 *
 */
V_FUNCTION_BEGIN(__kernel_gettimeofday)
  .cfi_startproc
	mflr	r0
	stwu	r1, -16(r1)
	stw	r0, 20(r1)
	stw	r3, 8(r1)
	stw	r4, 12(r1)
	bl	__c_kernel_gettimeofday
	cmpwi	r3, 0
	lwz	r0, 20(r1)
	mtlr	r0
	bne	99f
	addi	r1, r1, 16
	crclr	cr0*4+so
	blr
99:
	lwz	r3, 8(r1)
	lwz	r4, 12(r1)
	addi	r1, r1, 16
	li	r0, __NR_gettimeofday
	sc
	blr
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
	mflr	r0
	stwu	r1, -16(r1)
	stw	r0, 20(r1)
	stw	r3, 8(r1)
	stw	r4, 12(r1)
	bl	__c_kernel_clock_gettime
	cmpwi	r3, 0
	lwz	r0, 20(r1)
	mtlr	r0
	bne	99f
	addi	r1, r1, 16
	crclr	cr0*4+so
	blr
99:
	lwz	r3, 8(r1)
	lwz	r4, 12(r1)
	addi	r1, r1, 16
	li	r0, __NR_clock_gettime
	sc
	blr
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
	mflr	r0
	stwu	r1, -16(r1)
	stw	r0, 20(r1)
	stw	r3, 8(r1)
	stw	r4, 12(r1)
	bl	__c_kernel_clock_getres
	cmpwi	r3, 0
	lwz	r0, 20(r1)
	mtlr	r0
	bne	99f
	addi	r1, r1, 16
	crclr	cr0*4+so
	blr
99:
	lwz	r3, 8(r1)
	lwz	r4, 12(r1)
	addi	r1, r1, 16
	li	r0, __NR_clock_getres
	sc
	blr
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
	stwu	r1, -16(r1)
	stw	r0, 20(r1)
	bl	__c_kernel_time
	lwz	r0, 20(r1)
	crclr	cr0*4+so
	mtlr	r0
	addi	r1, r1, 16
	blr
  .cfi_endproc
V_FUNCTION_END(__kernel_time)
