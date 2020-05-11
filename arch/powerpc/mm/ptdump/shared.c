// SPDX-License-Identifier: GPL-2.0
/*
 * From split of dump_linuxpagetables.c
 * Copyright 2016, Rashmica Gupta, IBM Corp.
 *
 */
#include <linux/kernel.h>
#include <asm/pgtable.h>

#include "ptdump.h"

static const struct flag_info flag_array[] = {
	{
		.mask	= _PAGE_USER,
		.val	= _PAGE_USER,
		.set	= "ur",
		.clear	= "  ",
	}, {
		.mask	= _PAGE_RW,
		.val	= _PAGE_RW,
		.set	= "rw",
		.clear	= "r ",
	}, {
		.mask	= _PAGE_EXEC,
		.val	= _PAGE_EXEC,
		.set	= "x",
		.clear	= " ",
	}, {
		.mask	= _PAGE_PRESENT,
		.val	= _PAGE_PRESENT,
		.set	= "p",
		.clear	= " ",
	}, {
		.mask	= _PAGE_WRITETHRU,
		.val	= _PAGE_WRITETHRU,
		.set	= "w",
		.clear	= " ",
	}, {
		.mask	= _PAGE_NO_CACHE,
		.val	= _PAGE_NO_CACHE,
		.set	= "i",
		.clear	= " ",
	}, {
		.mask	= _PAGE_GUARDED,
		.val	= _PAGE_GUARDED,
		.set	= "g",
		.clear	= " ",
	}, {
		.mask	= _PAGE_SPECIAL,
		.val	= _PAGE_SPECIAL,
		.set	= "s",
		.clear	= " ",
	}, {
		.mask	= _PAGE_DIRTY,
		.val	= _PAGE_DIRTY,
		.set	= "d",
		.clear	= " ",
	}, {
		.mask	= _PAGE_ACCESSED,
		.val	= _PAGE_ACCESSED,
		.set	= "a",
		.clear	= " ",
	}
};

struct pgtable_level pg_level[5] = {
	{
	}, { /* pgd */
		.flag	= flag_array,
		.num	= ARRAY_SIZE(flag_array),
	}, { /* pud */
		.flag	= flag_array,
		.num	= ARRAY_SIZE(flag_array),
	}, { /* pmd */
		.flag	= flag_array,
		.num	= ARRAY_SIZE(flag_array),
	}, { /* pte */
		.flag	= flag_array,
		.num	= ARRAY_SIZE(flag_array),
	},
};
