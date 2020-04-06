/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_INST_H
#define _ASM_INST_H

/*
 * Instruction data type for POWER
 */

struct ppc_inst {
        u32 val;
#ifdef __powerpc64__
        u32 suffix;
#endif /* __powerpc64__ */
} __packed;

static inline int ppc_inst_opcode(struct ppc_inst x)
{
	return x.val >> 26;
}

static inline u32 ppc_inst_val(struct ppc_inst x)
{
	return x.val;
}

#ifdef __powerpc64__
#define ppc_inst(x) ((struct ppc_inst){ .val = (x), .suffix = 0xff })

#define ppc_inst_prefix(x, y) ((struct ppc_inst){ .val = (x), .suffix = (y) })

static inline u32 ppc_inst_suffix(struct ppc_inst x)
{
	return x.suffix;
}

static inline bool ppc_inst_prefixed(struct ppc_inst x) {
	return ((ppc_inst_val(x) >> 26) == 1) && ppc_inst_suffix(x) != 0xff;
}

static inline struct ppc_inst ppc_inst_swab(struct ppc_inst x)
{
	return ppc_inst_prefix(swab32(ppc_inst_val(x)),
			       swab32(ppc_inst_suffix(x)));
}

static inline struct ppc_inst ppc_inst_read(const struct ppc_inst *ptr)
{
	u32 val, suffix = 0xff;
	val = *(u32 *)ptr;
	if ((val >> 26) == 1)
		suffix = *((u32 *)ptr + 1);
	return ppc_inst_prefix(val, suffix);
}

static inline void ppc_inst_write(struct ppc_inst *ptr, struct ppc_inst x)
{
	if (ppc_inst_prefixed(x)) {
		*(u32 *)ptr = x.val;
		*((u32 *)ptr + 1) = x.suffix;
	} else {
		*(u32 *)ptr = x.val;
	}
}

#else

#define ppc_inst(x) ((struct ppc_inst){ .val = x })

static inline bool ppc_inst_prefixed(ppc_inst x)
{
	return 0;
}

static inline struct ppc_inst ppc_inst_swab(struct ppc_inst x)
{
	return ppc_inst(swab32(ppc_inst_val(x)));
}

static inline u32 ppc_inst_val(struct ppc_inst x)
{
	return x.val;
}

static inline struct ppc_inst ppc_inst_read(const struct ppc_inst *ptr)
{
	return *ptr;
}

static inline void ppc_inst_write(struct ppc_inst *ptr, struct ppc_inst x)
{
	*ptr = x;
}

#endif /* __powerpc64__ */

static inline bool ppc_inst_equal(struct ppc_inst x, struct ppc_inst y)
{
	return !memcmp(&x, &y, sizeof(struct ppc_inst));
}

static inline int ppc_inst_len(struct ppc_inst x)
{
	return (ppc_inst_prefixed(x)) ? 8  : 4;
}

#endif /* _ASM_INST_H */
