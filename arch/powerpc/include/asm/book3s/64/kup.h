/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_POWERPC_BOOK3S_64_KUP_H
#define _ASM_POWERPC_BOOK3S_64_KUP_H

#include <linux/const.h>
#include <asm/reg.h>

#define AMR_KUAP_BLOCK_READ	UL(0x4000000000000000)
#define AMR_KUAP_BLOCK_WRITE	UL(0x8000000000000000)
#define AMR_KUEP_BLOCKED	(1UL << 62)
#define AMR_KUAP_BLOCKED	(AMR_KUAP_BLOCK_READ | AMR_KUAP_BLOCK_WRITE)
#define AMR_KUAP_SHIFT		62

#ifdef __ASSEMBLY__

.macro kuap_restore_user_amr gpr1
#if defined(CONFIG_PPC_MEM_KEYS)
	BEGIN_MMU_FTR_SECTION_NESTED(67)
	/*
	 * AMR and IAMR are going to be different when
	 * returning to userspace.
	 */
	ld	\gpr1, STACK_REGS_KUAP(r1)
	isync
	mtspr	SPRN_AMR, \gpr1
	/*
	 * Restore IAMR only when returning to userspace
	 */
	ld	\gpr1, STACK_REGS_KUEP(r1)
	mtspr	SPRN_IAMR, \gpr1

	/* No isync required, see kuap_restore_user_amr() */
	END_MMU_FTR_SECTION_NESTED_IFSET(MMU_FTR_PKEY , 67)

	/*
	 * We don't check KUEP feature here, because if FTR_PKEY
	 * is not enabled we don't need to restore IAMR on
	 * return to usespace.
	 */
#endif
.endm

.macro kuap_restore_kernel_amr	gpr1, gpr2
#if defined(CONFIG_PPC_MEM_KEYS)
	BEGIN_MMU_FTR_SECTION_NESTED(67)
	b	99f  // handle_pkey_restore_amr
	END_MMU_FTR_SECTION_NESTED_IFSET(MMU_FTR_PKEY , 67)

	BEGIN_MMU_FTR_SECTION_NESTED(68)
	b	99f  // handle_kuap_restore_amr
	MMU_FTR_SECTION_ELSE_NESTED(68)
	b	100f  // skip_restore_amr
	ALT_MMU_FTR_SECTION_END_NESTED_IFSET(MMU_FTR_KUAP, 68)

99:
	/*
	 * AMR is going to be mostly the same since we are
	 * returning to the kernel. Compare and do a mtspr.
	 */
	ld	\gpr2, STACK_REGS_KUAP(r1)
	mfspr	\gpr1, SPRN_AMR
	cmpd	\gpr1, \gpr2
	beq	100f
	isync
	mtspr	SPRN_AMR, \gpr2
	/* No isync required, see kuap_restore_amr() */
	/*
	 * No need to restore IAMR when returning to kernel space.
	 */
100:  // skip_restore_amr
#endif
.endm

.macro kuap_check_amr gpr1, gpr2
#ifdef CONFIG_PPC_KUAP_DEBUG
	BEGIN_MMU_FTR_SECTION_NESTED(67)
	mfspr	\gpr1, SPRN_AMR
	li	\gpr2, (AMR_KUAP_BLOCKED >> AMR_KUAP_SHIFT)
	sldi	\gpr2, \gpr2, AMR_KUAP_SHIFT
999:	tdne	\gpr1, \gpr2
	EMIT_BUG_ENTRY 999b, __FILE__, __LINE__, (BUGFLAG_WARNING | BUGFLAG_ONCE)
	END_MMU_FTR_SECTION_NESTED_IFSET(MMU_FTR_KUAP, 67)
#endif
.endm

/*
 * MMU_FTR_PKEY and MMU_FTR_KUAP can both be enabled on a platform. We prefer
 * PKEY over KUAP if both can be enabled on the platform.
 *
 * With KUAP only enabled on exception if we are coming from userspace we don't
 * save the AMR at all, because the expectation is that userspace can't change
 * the AMR if KUAP feature is enabled.
 */
.macro kuap_save_amr_and_lock gpr1, gpr2, use_cr, msr_pr_cr
#if defined(CONFIG_PPC_MEM_KEYS)

	BEGIN_MMU_FTR_SECTION_NESTED(67)
	b	101f   // handle_pkey_save_amr
        END_MMU_FTR_SECTION_NESTED_IFSET(MMU_FTR_PKEY , 67)

	BEGIN_MMU_FTR_SECTION_NESTED(68)
	b	99f  // handle_kuap_save_amr
	MMU_FTR_SECTION_ELSE_NESTED(68)
	b	100f  // skip_save_amr
	ALT_MMU_FTR_SECTION_END_NESTED_IFSET(MMU_FTR_KUAP, 68)

	/*
	 * We don't check KUEP feature here, because if FTR_PKEY
	 * is not enabled we don't need to save IAMR on
	 * entry from usespace. That is handled by either
	 * handle_kuap_save_amr or skip_save_amr
	 */

99: // handle_kuap_save_amr
	.ifnb \msr_pr_cr
	/*
	 * We avoid changing AMR outside the kernel
	 * hence skip this completely.
	 */
	bne	\msr_pr_cr, 100f  // from userspace
	.endif

101:   // handle_pkey_save_amr
	mfspr	\gpr1, SPRN_AMR
	std	\gpr1, STACK_REGS_KUAP(r1)

	/*
	 * update kernel AMR with AMR_KUAP_BLOCKED only
	 * if KUAP feature is enabled
	 */
	BEGIN_MMU_FTR_SECTION_NESTED(69)
	LOAD_REG_IMMEDIATE(\gpr2, AMR_KUAP_BLOCKED)
	cmpd	\use_cr, \gpr1, \gpr2
	beq	\use_cr, 102f
	/*
	 * We don't isync here because we very recently entered via an interrupt
	 */
	mtspr	SPRN_AMR, \gpr2
	isync
102:
	END_MMU_FTR_SECTION_NESTED_IFSET(MMU_FTR_KUAP, 69)

	.ifnb \msr_pr_cr
	beq	\msr_pr_cr, 103f // from kernel space
	mfspr	\gpr1, SPRN_IAMR
	std	\gpr1, STACK_REGS_KUEP(r1)

	/*
	 * update kernel IAMR with AMR_KUEP_BLOCKED only
	 * if KUEP feature is enabled
	 */
	BEGIN_MMU_FTR_SECTION_NESTED(70)
	LOAD_REG_IMMEDIATE(\gpr2, AMR_KUEP_BLOCKED)
	cmpd	\use_cr, \gpr1, \gpr2
	beq	\use_cr, 103f
	mtspr	SPRN_IAMR, \gpr2
	isync
103:
	END_MMU_FTR_SECTION_NESTED_IFSET(MMU_FTR_KUEP, 70)
	.endif

100: // skip_save_amr
#endif
.endm

#else /* !__ASSEMBLY__ */

#ifdef CONFIG_PPC_MEM_KEYS

#include <asm/mmu.h>
#include <asm/ptrace.h>

extern u64 default_uamor;

static inline void kuap_restore_user_amr(struct pt_regs *regs)
{
	if (!mmu_has_feature(MMU_FTR_PKEY))
		return;

	isync();
	mtspr(SPRN_AMR, regs->kuap);
	mtspr(SPRN_IAMR, regs->kuep);
	/*
	 * No isync required here because we are about to rfi
	 * back to previous context before any user accesses
	 * would be made, which is a CSI.
	 */
}
static inline void kuap_restore_kernel_amr(struct pt_regs *regs,
					   unsigned long amr)
{
	if (mmu_has_feature(MMU_FTR_KUAP) || mmu_has_feature(MMU_FTR_PKEY)) {

		if (unlikely(regs->kuap != amr)) {
			isync();
			mtspr(SPRN_AMR, regs->kuap);
			/*
			 * No isync required here because we are about to rfi
			 * back to previous context before any user accesses
			 * would be made, which is a CSI.
			 */
		}
	}
	/*
	 * No need to restore IAMR when returning to kernel space.
	 */
}

static inline unsigned long kuap_get_and_check_amr(void)
{
	if (mmu_has_feature(MMU_FTR_KUAP) || mmu_has_feature(MMU_FTR_PKEY)) {
		unsigned long amr = mfspr(SPRN_AMR);
		if (IS_ENABLED(CONFIG_PPC_KUAP_DEBUG)) /* kuap_check_amr() */
			WARN_ON_ONCE(amr != AMR_KUAP_BLOCKED);
		return amr;
	}
	return 0;
}

static inline void kuap_check_amr(void)
{
	if (IS_ENABLED(CONFIG_PPC_KUAP_DEBUG) &&
	    (mmu_has_feature(MMU_FTR_KUAP) || mmu_has_feature(MMU_FTR_PKEY)))
		WARN_ON_ONCE(mfspr(SPRN_AMR) != AMR_KUAP_BLOCKED);
}

/*
 * We support individually allowing read or write, but we don't support nesting
 * because that would require an expensive read/modify write of the AMR.
 */

static inline unsigned long get_kuap(void)
{
	if (!early_mmu_has_feature(MMU_FTR_KUAP))
		return 0;

	return mfspr(SPRN_AMR);
}

static inline void set_kuap(unsigned long value)
{
	if (!early_mmu_has_feature(MMU_FTR_KUAP))
		return;

	/*
	 * ISA v3.0B says we need a CSI (Context Synchronising Instruction) both
	 * before and after the move to AMR. See table 6 on page 1134.
	 */
	isync();
	mtspr(SPRN_AMR, value);
	isync();
}

static __always_inline void allow_user_access(void __user *to, const void __user *from,
					      unsigned long size, unsigned long dir)
{
	// This is written so we can resolve to a single case at build time
	BUILD_BUG_ON(!__builtin_constant_p(dir));
	if (dir == KUAP_READ)
		set_kuap(AMR_KUAP_BLOCK_WRITE);
	else if (dir == KUAP_WRITE)
		set_kuap(AMR_KUAP_BLOCK_READ);
	else if (dir == KUAP_READ_WRITE)
		set_kuap(0);
	else
		BUILD_BUG();
}

static inline void prevent_user_access(void __user *to, const void __user *from,
				       unsigned long size, unsigned long dir)
{
	set_kuap(AMR_KUAP_BLOCKED);
}

static inline unsigned long prevent_user_access_return(void)
{
	unsigned long flags = get_kuap();

	set_kuap(AMR_KUAP_BLOCKED);

	return flags;
}

static inline void restore_user_access(unsigned long flags)
{
	set_kuap(flags);
}

static inline bool
bad_kuap_fault(struct pt_regs *regs, unsigned long address, bool is_write)
{
	return WARN(mmu_has_feature(MMU_FTR_KUAP) &&
		    (regs->kuap & (is_write ? AMR_KUAP_BLOCK_WRITE : AMR_KUAP_BLOCK_READ)),
		    "Bug: %s fault blocked by AMR!", is_write ? "Write" : "Read");
}
#else /* CONFIG_PPC_MEM_KEYS */
static inline void kuap_restore_user_amr(struct pt_regs *regs)
{
}

static inline void kuap_restore_kernel_amr(struct pt_regs *regs, unsigned long amr)
{
}

static inline void kuap_check_amr(void)
{
}

static inline unsigned long kuap_get_and_check_amr(void)
{
	return 0;
}
#endif /* CONFIG_PPC_MEM_KEYS */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_POWERPC_BOOK3S_64_KUP_H */
