/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *
 * Copyright IBM Corp. 2008
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef __ASM_PPC_DISASSEMBLE_H__
#define __ASM_PPC_DISASSEMBLE_H__

#include <linux/types.h>
#include <asm/inst.h>

static inline unsigned int get_op(struct ppc_inst inst)
{
	return ppc_inst_val(inst) >> 26;
}

static inline unsigned int get_xop(struct ppc_inst inst)
{
	return (ppc_inst_val(inst) >> 1) & 0x3ff;
}

static inline unsigned int get_sprn(struct ppc_inst inst)
{
	u32 word = ppc_inst_val(inst);

	return ((word >> 16) & 0x1f) | ((word >> 6) & 0x3e0);
}

static inline unsigned int get_dcrn(struct ppc_inst inst)
{
	u32 word = ppc_inst_val(inst);

	return ((word >> 16) & 0x1f) | ((word >> 6) & 0x3e0);
}

static inline unsigned int get_tmrn(struct ppc_inst inst)
{
	u32 word = ppc_inst_val(inst);

	return ((word >> 16) & 0x1f) | ((word >> 6) & 0x3e0);
}

static inline unsigned int get_rt(struct ppc_inst inst)
{
	return (ppc_inst_val(inst) >> 21) & 0x1f;
}

static inline unsigned int get_rs(struct ppc_inst inst)
{
	return (ppc_inst_val(inst) >> 21) & 0x1f;
}

static inline unsigned int get_ra(struct ppc_inst inst)
{
	return (ppc_inst_val(inst) >> 16) & 0x1f;
}

static inline unsigned int get_rb(struct ppc_inst inst)
{
	return (ppc_inst_val(inst) >> 11) & 0x1f;
}

static inline unsigned int get_rc(struct ppc_inst inst)
{
	return ppc_inst_val(inst) & 0x1;
}

static inline unsigned int get_ws(struct ppc_inst inst)
{
	return (ppc_inst_val(inst) >> 11) & 0x1f;
}

static inline unsigned int get_d(struct ppc_inst inst)
{
	return ppc_inst_val(inst) & 0xffff;
}

static inline unsigned int get_oc(struct ppc_inst inst)
{
	return (ppc_inst_val(inst) >> 11) & 0x7fff;
}

static inline unsigned int get_tx_or_sx(struct ppc_inst inst)
{
	return (ppc_inst_val(inst)) & 0x1;
}

#define IS_XFORM(inst)	(get_op(inst)  == 31)
#define IS_DSFORM(inst)	(get_op(inst) >= 56)

/*
 * Create a DSISR value from the instruction
 */
static inline unsigned make_dsisr(struct ppc_inst instr)
{
	unsigned dsisr;
	u32 word = ppc_inst_val(instr);


	/* bits  6:15 --> 22:31 */
	dsisr = (word & 0x03ff0000) >> 16;

	if (IS_XFORM(instr)) {
		/* bits 29:30 --> 15:16 */
		dsisr |= (word & 0x00000006) << 14;
		/* bit     25 -->    17 */
		dsisr |= (word & 0x00000040) << 8;
		/* bits 21:24 --> 18:21 */
		dsisr |= (word & 0x00000780) << 3;
	} else {
		/* bit      5 -->    17 */
		dsisr |= (word & 0x04000000) >> 12;
		/* bits  1: 4 --> 18:21 */
		dsisr |= (word & 0x78000000) >> 17;
		/* bits 30:31 --> 12:13 */
		if (IS_DSFORM(instr))
			dsisr |= (word & 0x00000003) << 18;
	}

	return dsisr;
}
#endif /* __ASM_PPC_DISASSEMBLE_H__ */
