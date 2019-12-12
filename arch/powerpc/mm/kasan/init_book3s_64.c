// SPDX-License-Identifier: GPL-2.0
/*
 * KASAN for 64-bit Book3S powerpc
 *
 * Copyright (C) 2019 IBM Corporation
 * Author: Daniel Axtens <dja@axtens.net>
 */

#define DISABLE_BRANCH_PROFILING

#include <linux/kasan.h>
#include <linux/printk.h>
#include <linux/sched/task.h>
#include <asm/pgalloc.h>

void __init kasan_init(void)
{
	int i;
	void *k_start = kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
	void *k_end = kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);

	pte_t pte = __pte(__pa(kasan_early_shadow_page) |
			  pgprot_val(PAGE_KERNEL) | _PAGE_PTE);

	if (!early_radix_enabled())
		panic("KASAN requires radix!");

	for (i = 0; i < PTRS_PER_PTE; i++)
		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
			     &kasan_early_shadow_pte[i], pte, 0);

	for (i = 0; i < PTRS_PER_PMD; i++)
		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
				    kasan_early_shadow_pte);

	for (i = 0; i < PTRS_PER_PUD; i++)
		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
			     kasan_early_shadow_pmd);

	memset(kasan_mem_to_shadow((void *)PAGE_OFFSET), KASAN_SHADOW_INIT,
	       KASAN_SHADOW_SIZE);

	kasan_populate_early_shadow(
		kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START),
		kasan_mem_to_shadow((void *)RADIX_VMALLOC_START));

	/* leave a hole here for vmalloc */

	kasan_populate_early_shadow(
		kasan_mem_to_shadow((void *)RADIX_VMALLOC_END),
		kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END));

	flush_tlb_kernel_range((unsigned long)k_start, (unsigned long)k_end);

	/* mark early shadow region as RO and wipe */
	pte = __pte(__pa(kasan_early_shadow_page) |
		    pgprot_val(PAGE_KERNEL_RO) | _PAGE_PTE);
	for (i = 0; i < PTRS_PER_PTE; i++)
		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
			     &kasan_early_shadow_pte[i], pte, 0);

	/*
	 * clear_page relies on some cache info that hasn't been set up yet.
	 * It ends up looping ~forever and blows up other data.
	 * Use memset instead.
	 */
	memset(kasan_early_shadow_page, 0, PAGE_SIZE);

	/* Enable error messages */
	init_task.kasan_depth = 0;
	pr_info("KASAN init done (64-bit Book3S heavyweight mode)\n");
}
