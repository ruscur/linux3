// SPDX-License-Identifier: GPL-2.0

/*
 * MMU-generic set_memory implementation for powerpc
 *
 * Author: Russell Currey <ruscur@russell.cc>
 *
 * Copyright 2019, IBM Corporation.
 */

#include <linux/mm.h>
#include <linux/set_memory.h>

#include <asm/mmu.h>
#include <asm/page.h>
#include <asm/pgtable.h>

static int change_page_attr(pte_t *ptep, unsigned long addr, void *data)
{
	int action = *((int *)data);
	pte_t pte_val;

	// invalidate the PTE so it's safe to modify
	pte_val = ptep_get_and_clear(&init_mm, addr, ptep);
	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);

	// modify the PTE bits as desired, then apply
	switch (action) {
	case SET_MEMORY_RO:
		pte_val = pte_wrprotect(pte_val);
		break;
	case SET_MEMORY_RW:
		pte_val = pte_mkwrite(pte_val);
		break;
	case SET_MEMORY_NX:
		pte_val = pte_exprotect(pte_val);
		break;
	case SET_MEMORY_X:
		pte_val = pte_mkexec(pte_val);
		break;
	default:
		WARN_ON(true);
		return -EINVAL;
	}

	set_pte_at(&init_mm, addr, ptep, pte_val);

	return 0;
}

int change_memory_attr(unsigned long addr, int numpages, int action)
{
	unsigned long start = ALIGN_DOWN(addr, PAGE_SIZE);
	unsigned long size = numpages * PAGE_SIZE;

	if (!numpages)
		return 0;

	return apply_to_page_range(&init_mm, start, size, change_page_attr, &action);
}
