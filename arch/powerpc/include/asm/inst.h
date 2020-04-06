/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_INST_H
#define _ASM_INST_H

/*
 * Instruction data type for POWER
 */

struct ppc_inst {
        u32 val;
} __packed;

#define ppc_inst(x) ((struct ppc_inst){ .val = x })

static inline u32 ppc_inst_val(struct ppc_inst x)
{
	return x.val;
}

static inline int ppc_inst_opcode(struct ppc_inst x)
{
	return x.val >> 26;
}

static inline struct ppc_inst ppc_inst_swab(struct ppc_inst x)
{
	return ppc_inst(swab32(ppc_inst_val(x)));
}

static inline struct ppc_inst ppc_inst_read(const struct ppc_inst *ptr)
{
	return *ptr;
}

static inline bool ppc_inst_equal(struct ppc_inst x, struct ppc_inst y)
{
	return !memcmp(&x, &y, sizeof(struct ppc_inst));
}

#endif /* _ASM_INST_H */
