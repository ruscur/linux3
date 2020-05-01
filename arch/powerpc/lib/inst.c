// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright 2020, IBM Corporation.
 */

#include <linux/uaccess.h>
#include <asm/inst.h>

#ifdef __powerpc64__
int probe_user_read_inst(struct ppc_inst *inst,
			 struct ppc_inst *nip)
{
	unsigned int val, suffix;
	int err;

	err = probe_user_read(&val, nip, sizeof(val));
	if (err)
		return err;
	if ((val >> 26) == 1) {
		err = probe_user_read(&suffix, (void *)nip+4,
				      sizeof(unsigned int));
		*inst = ppc_inst_prefix(val, suffix);
	} else {
		*inst = ppc_inst(val);
	}
	return err;
}

int probe_kernel_read_inst(struct ppc_inst *inst,
			   struct ppc_inst *src)
{
	unsigned int val, suffix;
	int err;

	err = probe_kernel_read(&val, src, sizeof(val));
	if (err)
		return err;
	if ((val >> 26) == 1) {
		err = probe_kernel_read(&suffix, (void *)src+4,
				      sizeof(unsigned int));
		*inst = ppc_inst_prefix(val, suffix);
	} else {
		*inst = ppc_inst(val);
	}
	return err;
}
#else
int probe_user_read_inst(struct ppc_inst *inst,
			 struct ppc_inst *nip)
{
	unsigned int val;
	int err;

	err = probe_user_read(&val, nip, sizeof(val));
	*inst = ppc_inst(val);
	return err;
}

int probe_kernel_read_inst(struct ppc_inst *inst,
			   struct ppc_inst *src)
{
	unsigned int val;
	int err;

	err = probe_kernel_read(&val, src, sizeof(val));
	*inst = ppc_inst(val);
	return err;
}
#endif /* __powerpc64__ */
