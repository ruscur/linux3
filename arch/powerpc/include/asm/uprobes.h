/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_UPROBES_H
#define _ASM_UPROBES_H
/*
 * User-space Probes (UProbes) for powerpc
 *
 * Copyright IBM Corporation, 2007-2012
 *
 * Adapted from the x86 port by Ananth N Mavinakayanahalli <ananth@in.ibm.com>
 */

#include <linux/notifier.h>
#include <asm/probes.h>

typedef ppc_opcode_t uprobe_opcode_t;

/*
 * Ensure we have enough space for prefixed instructions, which
 * are double the size of a word instruction, i.e. 8 bytes.
 */
#define MAX_UINSN_BYTES		4
#define UPROBE_XOL_SLOT_BYTES	(2 * MAX_UINSN_BYTES)

/* The following alias is needed for reference from arch-agnostic code */
#define UPROBE_SWBP_INSN	BREAKPOINT_INSTRUCTION
#define UPROBE_SWBP_INSN_SIZE	4 /* swbp insn size in bytes */

struct arch_uprobe {
	 /*
	  * Ensure there is enough space for prefixed instructions. Prefixed
	  * instructions must not cross 64-byte boundaries.
	  */
	union {
		uprobe_opcode_t	insn[2];
		uprobe_opcode_t	ixol[2];
	} __aligned(64);
};

struct arch_uprobe_task {
	unsigned long	saved_trap_nr;
};

#endif	/* _ASM_UPROBES_H */
