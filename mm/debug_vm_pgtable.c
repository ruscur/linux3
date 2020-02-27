// SPDX-License-Identifier: GPL-2.0-only
/*
 * This kernel test validates architecture page table helpers and
 * accessors and helps in verifying their continued compliance with
 * expected generic MM semantics.
 *
 * Copyright (C) 2019 ARM Ltd.
 *
 * Author: Anshuman Khandual <anshuman.khandual@arm.com>
 */
#define pr_fmt(fmt) "debug_vm_pgtable: %s: " fmt, __func__

#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/kconfig.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/pfn_t.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/start_kernel.h>
#include <linux/sched/mm.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>

/*
 * Basic operations
 *
 * mkold(entry)			= An old and not a young entry
 * mkyoung(entry)		= A young and not an old entry
 * mkdirty(entry)		= A dirty and not a clean entry
 * mkclean(entry)		= A clean and not a dirty entry
 * mkwrite(entry)		= A write and not a write protected entry
 * wrprotect(entry)		= A write protected and not a write entry
 * pxx_bad(entry)		= A mapped and non-table entry
 * pxx_same(entry1, entry2)	= Both entries hold the exact same value
 *
 * Specific feature operations
 *
 * pte_mkspecial(entry)		= Creates a special entry at PTE level
 * pte_special(entry)		= Tests a special entry at PTE level
 *
 * pte_protnone(entry)		= Tests a no access entry at PTE level
 * pmd_protnone(entry)		= Tests a no access entry at PMD level
 *
 * pte_mkdevmap(entry)		= Creates a device entry at PTE level
 * pmd_mkdevmap(entry)		= Creates a device entry at PMD level
 * pud_mkdevmap(entry)		= Creates a device entry at PUD level
 * pte_devmap(entry)		= Tests a device entry at PTE level
 * pmd_devmap(entry)		= Tests a device entry at PMD level
 * pud_devmap(entry)		= Tests a device entry at PUD level
 *
 * pte_mksoft_dirty(entry)	= Creates a soft dirty entry at PTE level
 * pmd_mksoft_dirty(entry)	= Creates a soft dirty entry at PMD level
 * pte_swp_mksoft_dirty(entry)	= Creates a soft dirty swap entry at PTE level
 * pmd_swp_mksoft_dirty(entry)	= Creates a soft dirty swap entry at PMD level
 * pte_soft_dirty(entry)	= Tests a soft dirty entry at PTE level
 * pmd_soft_dirty(entry)	= Tests a soft dirty entry at PMD level
 * pte_swp_soft_dirty(entry)	= Tests a soft dirty swap entry at PTE level
 * pmd_swp_soft_dirty(entry)	= Tests a soft dirty swap entry at PMD level
 * pte_clear_soft_dirty(entry)	   = Clears a soft dirty entry at PTE level
 * pmd_clear_soft_dirty(entry)	   = Clears a soft dirty entry at PMD level
 * pte_swp_clear_soft_dirty(entry) = Clears a soft dirty swap entry at PTE level
 * pmd_swp_clear_soft_dirty(entry) = Clears a soft dirty swap entry at PMD level
 *
 * pte_mkhuge(entry)		= Creates a HugeTLB entry at given level
 * pte_huge(entry)		= Tests a HugeTLB entry at given level
 *
 * pmd_trans_huge(entry)	= Tests a trans huge page at PMD level
 * pud_trans_huge(entry)	= Tests a trans huge page at PUD level
 * pmd_present(entry)		= Tests an entry points to memory at PMD level
 * pud_present(entry)		= Tests an entry points to memory at PUD level
 * pmd_mknotpresent(entry)	= Invalidates an PMD entry for MMU
 * pud_mknotpresent(entry)	= Invalidates an PUD entry for MMU
 */
#define VMFLAGS	(VM_READ|VM_WRITE|VM_EXEC)

/*
 * On s390 platform, the lower 4 bits are used to identify given page table
 * entry type. But these bits might affect the ability to clear entries with
 * pxx_clear() because of how dynamic page table folding works on s390. So
 * while loading up the entries do not change the lower 4 bits. It does not
 * have affect any other platform.
 */
#define S390_MASK_BITS	4
#define RANDOM_ORVALUE	GENMASK(BITS_PER_LONG - 1, S390_MASK_BITS)
#define RANDOM_NZVALUE	GENMASK(7, 0)

static void __init pte_basic_tests(unsigned long pfn, pgprot_t prot)
{
	pte_t pte = pfn_pte(pfn, prot);

	WARN_ON(!pte_same(pte, pte));
	WARN_ON(!pte_young(pte_mkyoung(pte_mkold(pte))));
	WARN_ON(!pte_dirty(pte_mkdirty(pte_mkclean(pte))));
	WARN_ON(!pte_write(pte_mkwrite(pte_wrprotect(pte))));
	WARN_ON(pte_young(pte_mkold(pte_mkyoung(pte))));
	WARN_ON(pte_dirty(pte_mkclean(pte_mkdirty(pte))));
	WARN_ON(pte_write(pte_wrprotect(pte_mkwrite(pte))));
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static void __init pmd_basic_tests(unsigned long pfn, pgprot_t prot)
{
	pmd_t pmd = pfn_pmd(pfn, prot);

	WARN_ON(!pmd_same(pmd, pmd));
	WARN_ON(!pmd_young(pmd_mkyoung(pmd_mkold(pmd))));
	WARN_ON(!pmd_dirty(pmd_mkdirty(pmd_mkclean(pmd))));
	WARN_ON(!pmd_write(pmd_mkwrite(pmd_wrprotect(pmd))));
	WARN_ON(pmd_young(pmd_mkold(pmd_mkyoung(pmd))));
	WARN_ON(pmd_dirty(pmd_mkclean(pmd_mkdirty(pmd))));
	WARN_ON(pmd_write(pmd_wrprotect(pmd_mkwrite(pmd))));
	/*
	 * A huge page does not point to next level page table
	 * entry. Hence this must qualify as pmd_bad().
	 */
	WARN_ON(!pmd_bad(pmd_mkhuge(pmd)));
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static void __init pud_basic_tests(unsigned long pfn, pgprot_t prot)
{
	pud_t pud = pfn_pud(pfn, prot);

	WARN_ON(!pud_same(pud, pud));
	WARN_ON(!pud_young(pud_mkyoung(pud_mkold(pud))));
	WARN_ON(!pud_write(pud_mkwrite(pud_wrprotect(pud))));
	WARN_ON(pud_write(pud_wrprotect(pud_mkwrite(pud))));
	WARN_ON(pud_young(pud_mkold(pud_mkyoung(pud))));

	if (mm_pmd_folded(mm))
		return;

	/*
	 * A huge page does not point to next level page table
	 * entry. Hence this must qualify as pud_bad().
	 */
	WARN_ON(!pud_bad(pud_mkhuge(pud)));
}
#else
static void __init pud_basic_tests(unsigned long pfn, pgprot_t prot) { }
#endif
#else
static void __init pmd_basic_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pud_basic_tests(unsigned long pfn, pgprot_t prot) { }
#endif

static void __init p4d_basic_tests(unsigned long pfn, pgprot_t prot)
{
	p4d_t p4d;

	memset(&p4d, RANDOM_NZVALUE, sizeof(p4d_t));
	WARN_ON(!p4d_same(p4d, p4d));
}

static void __init pgd_basic_tests(unsigned long pfn, pgprot_t prot)
{
	pgd_t pgd;

	memset(&pgd, RANDOM_NZVALUE, sizeof(pgd_t));
	WARN_ON(!pgd_same(pgd, pgd));
}

#ifndef __PAGETABLE_PUD_FOLDED
static void __init pud_clear_tests(struct mm_struct *mm, pud_t *pudp)
{
	pud_t pud = READ_ONCE(*pudp);

	if (mm_pmd_folded(mm))
		return;

	pud = __pud(pud_val(pud) | RANDOM_ORVALUE);
	WRITE_ONCE(*pudp, pud);
	pud_clear(pudp);
	pud = READ_ONCE(*pudp);
	WARN_ON(!pud_none(pud));
}

static void __init pud_populate_tests(struct mm_struct *mm, pud_t *pudp,
				      pmd_t *pmdp)
{
	pud_t pud;

	if (mm_pmd_folded(mm))
		return;
	/*
	 * This entry points to next level page table page.
	 * Hence this must not qualify as pud_bad().
	 */
	pmd_clear(pmdp);
	pud_clear(pudp);
	pud_populate(mm, pudp, pmdp);
	pud = READ_ONCE(*pudp);
	WARN_ON(pud_bad(pud));
}
#else
static void __init pud_clear_tests(struct mm_struct *mm, pud_t *pudp) { }
static void __init pud_populate_tests(struct mm_struct *mm, pud_t *pudp,
				      pmd_t *pmdp)
{
}
#endif

#ifndef __PAGETABLE_P4D_FOLDED
static void __init p4d_clear_tests(struct mm_struct *mm, p4d_t *p4dp)
{
	p4d_t p4d = READ_ONCE(*p4dp);

	if (mm_pud_folded(mm))
		return;

	p4d = __p4d(p4d_val(p4d) | RANDOM_ORVALUE);
	WRITE_ONCE(*p4dp, p4d);
	p4d_clear(p4dp);
	p4d = READ_ONCE(*p4dp);
	WARN_ON(!p4d_none(p4d));
}

static void __init p4d_populate_tests(struct mm_struct *mm, p4d_t *p4dp,
				      pud_t *pudp)
{
	p4d_t p4d;

	if (mm_pud_folded(mm))
		return;

	/*
	 * This entry points to next level page table page.
	 * Hence this must not qualify as p4d_bad().
	 */
	pud_clear(pudp);
	p4d_clear(p4dp);
	p4d_populate(mm, p4dp, pudp);
	p4d = READ_ONCE(*p4dp);
	WARN_ON(p4d_bad(p4d));
}

static void __init pgd_clear_tests(struct mm_struct *mm, pgd_t *pgdp)
{
	pgd_t pgd = READ_ONCE(*pgdp);

	if (mm_p4d_folded(mm))
		return;

	pgd = __pgd(pgd_val(pgd) | RANDOM_ORVALUE);
	WRITE_ONCE(*pgdp, pgd);
	pgd_clear(pgdp);
	pgd = READ_ONCE(*pgdp);
	WARN_ON(!pgd_none(pgd));
}

static void __init pgd_populate_tests(struct mm_struct *mm, pgd_t *pgdp,
				      p4d_t *p4dp)
{
	pgd_t pgd;

	if (mm_p4d_folded(mm))
		return;

	/*
	 * This entry points to next level page table page.
	 * Hence this must not qualify as pgd_bad().
	 */
	p4d_clear(p4dp);
	pgd_clear(pgdp);
	pgd_populate(mm, pgdp, p4dp);
	pgd = READ_ONCE(*pgdp);
	WARN_ON(pgd_bad(pgd));
}
#else
static void __init p4d_clear_tests(struct mm_struct *mm, p4d_t *p4dp) { }
static void __init pgd_clear_tests(struct mm_struct *mm, pgd_t *pgdp) { }
static void __init p4d_populate_tests(struct mm_struct *mm, p4d_t *p4dp,
				      pud_t *pudp)
{
}
static void __init pgd_populate_tests(struct mm_struct *mm, pgd_t *pgdp,
				      p4d_t *p4dp)
{
}
#endif

static void __init pte_clear_tests(struct mm_struct *mm, pte_t *ptep)
{
	pte_t pte = READ_ONCE(*ptep);

	pte = __pte(pte_val(pte) | RANDOM_ORVALUE);
	WRITE_ONCE(*ptep, pte);
	pte_clear(mm, 0, ptep);
	pte = READ_ONCE(*ptep);
	WARN_ON(!pte_none(pte));
}

static void __init pmd_clear_tests(struct mm_struct *mm, pmd_t *pmdp)
{
	pmd_t pmd = READ_ONCE(*pmdp);

	pmd = __pmd(pmd_val(pmd) | RANDOM_ORVALUE);
	WRITE_ONCE(*pmdp, pmd);
	pmd_clear(pmdp);
	pmd = READ_ONCE(*pmdp);
	WARN_ON(!pmd_none(pmd));
}

static void __init pmd_populate_tests(struct mm_struct *mm, pmd_t *pmdp,
				      pgtable_t pgtable)
{
	pmd_t pmd;

	/*
	 * This entry points to next level page table page.
	 * Hence this must not qualify as pmd_bad().
	 */
	pmd_clear(pmdp);
	pmd_populate(mm, pmdp, pgtable);
	pmd = READ_ONCE(*pmdp);
	WARN_ON(pmd_bad(pmd));
}

#ifdef CONFIG_ARCH_HAS_PTE_SPECIAL
static void __init pte_special_tests(unsigned long pfn, pgprot_t prot)
{
	pte_t pte = pfn_pte(pfn, prot);

	WARN_ON(!pte_special(pte_mkspecial(pte)));
}
#else
static void __init pte_special_tests(unsigned long pfn, pgprot_t prot) { }
#endif

#ifdef CONFIG_NUMA_BALANCING
static void __init pte_protnone_tests(unsigned long pfn, pgprot_t prot)
{
	pte_t pte = pfn_pte(pfn, prot);

	WARN_ON(!pte_protnone(pte));
	WARN_ON(!pte_present(pte));
}

static void __init pmd_protnone_tests(unsigned long pfn, pgprot_t prot)
{
	pmd_t pmd = pfn_pmd(pfn, prot);

	WARN_ON(!pmd_protnone(pmd));
	WARN_ON(!pmd_present(pmd));
}
#else
static void __init pte_protnone_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pmd_protnone_tests(unsigned long pfn, pgprot_t prot) { }
#endif

#ifdef CONFIG_ARCH_HAS_PTE_DEVMAP
static void __init pte_devmap_tests(unsigned long pfn, pgprot_t prot)
{
	pte_t pte = pfn_pte(pfn, prot);

	WARN_ON(!pte_devmap(pte_mkdevmap(pte)));
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static void __init pmd_devmap_tests(unsigned long pfn, pgprot_t prot)
{
	pmd_t pmd = pfn_pmd(pfn, prot);

	WARN_ON(!pmd_devmap(pmd_mkdevmap(pmd)));
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static void __init pud_devmap_tests(unsigned long pfn, pgprot_t prot)
{
	pud_t pud = pfn_pud(pfn, prot);

	WARN_ON(!pud_devmap(pud_mkdevmap(pud)));
}
#else
static void __init pud_devmap_tests(unsigned long pfn, pgprot_t prot) { }
#endif
#else
static void __init pmd_devmap_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pud_devmap_tests(unsigned long pfn, pgprot_t prot) { }
#endif
#else
static void __init pte_devmap_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pmd_devmap_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pud_devmap_tests(unsigned long pfn, pgprot_t prot) { }
#endif

#ifdef CONFIG_MEM_SOFT_DIRTY
static void __init pte_soft_dirty_tests(unsigned long pfn, pgprot_t prot)
{
	pte_t pte = pfn_pte(pfn, prot);

	WARN_ON(!pte_soft_dirty(pte_mksoft_dirty(pte)));
	WARN_ON(pte_soft_dirty(pte_clear_soft_dirty(pte)));
}

static void __init pte_swap_soft_dirty_tests(unsigned long pfn, pgprot_t prot)
{
	pte_t pte = pfn_pte(pfn, prot);

	WARN_ON(!pte_swp_soft_dirty(pte_swp_mksoft_dirty(pte)));
	WARN_ON(pte_swp_soft_dirty(pte_swp_clear_soft_dirty(pte)));
}

#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
static void __init pmd_soft_dirty_tests(unsigned long pfn, pgprot_t prot)
{
	pmd_t pmd = pfn_pmd(pfn, prot);

	WARN_ON(!pmd_soft_dirty(pmd_mksoft_dirty(pmd)));
	WARN_ON(pmd_soft_dirty(pmd_clear_soft_dirty(pmd)));
}

static void __init pmd_swap_soft_dirty_tests(unsigned long pfn, pgprot_t prot)
{
	pmd_t pmd = pfn_pmd(pfn, prot);

	WARN_ON(!pmd_swp_soft_dirty(pmd_swp_mksoft_dirty(pmd)));
	WARN_ON(pmd_swp_soft_dirty(pmd_swp_clear_soft_dirty(pmd)));
}
#else
static void __init pmd_soft_dirty_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pmd_swap_soft_dirty_tests(unsigned long pfn, pgprot_t prot)
{
}
#endif
#else
static void __init pte_soft_dirty_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pmd_soft_dirty_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pte_swap_soft_dirty_tests(unsigned long pfn, pgprot_t prot)
{
}
static void __init pmd_swap_soft_dirty_tests(unsigned long pfn, pgprot_t prot)
{
}
#endif

static void __init pte_swap_tests(unsigned long pfn, pgprot_t prot)
{
	swp_entry_t swp;
	pte_t pte;

	pte = pfn_pte(pfn, prot);
	swp = __pte_to_swp_entry(pte);
	WARN_ON(!pte_same(pte, __swp_entry_to_pte(swp)));
}

#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
static void __init pmd_swap_tests(unsigned long pfn, pgprot_t prot)
{
	swp_entry_t swp;
	pmd_t pmd;

	pmd = pfn_pmd(pfn, prot);
	swp = __pmd_to_swp_entry(pmd);
	WARN_ON(!pmd_same(pmd, __swp_entry_to_pmd(swp)));
}
#else
static void __init pmd_swap_tests(unsigned long pfn, pgprot_t prot) { }
#endif

#ifdef CONFIG_MIGRATION
static void __init swap_migration_tests(struct page *page)
{
	swp_entry_t swp;

	/*
	 * make_migration_entry() expects given page to be
	 * locked, otherwise it stumbles upon a BUG_ON().
	 */
	__SetPageLocked(page);
	swp = make_migration_entry(page, 1);
	WARN_ON(!is_migration_entry(swp));
	WARN_ON(!is_write_migration_entry(swp));

	make_migration_entry_read(&swp);
	WARN_ON(!is_migration_entry(swp));
	WARN_ON(is_write_migration_entry(swp));

	swp = make_migration_entry(page, 0);
	WARN_ON(!is_migration_entry(swp));
	WARN_ON(is_write_migration_entry(swp));
	__ClearPageLocked(page);
}
#else
static void __init swap_migration_tests(struct page *page) { }
#endif

#ifdef CONFIG_HUGETLB_PAGE
static void __init hugetlb_tests(unsigned long pfn, pgprot_t prot)
{
#ifdef CONFIG_ARCH_WANT_GENERAL_HUGETLB
	pte_t pte = pfn_pte(pfn, prot);

	WARN_ON(!pte_huge(pte_mkhuge(pte)));
#endif
}
#else
static void __init hugetlb_tests(unsigned long pfn, pgprot_t prot) { }
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static void __init pmd_thp_tests(unsigned long pfn, pgprot_t prot)
{
	pmd_t pmd;

	/*
	 * pmd_trans_huge() and pmd_present() must return negative
	 * after MMU invalidation with pmd_mknotpresent().
	 */
	pmd = pfn_pmd(pfn, prot);
	WARN_ON(!pmd_trans_huge(pmd_mkhuge(pmd)));

	/*
	 * Though platform specific test exclusions are not ideal,
	 * in this case S390 does not define pmd_mknotpresent()
	 * which should be tested on other platforms enabling THP.
	 */
#ifndef CONFIG_S390
	WARN_ON(pmd_trans_huge(pmd_mknotpresent(pmd)));
	WARN_ON(pmd_present(pmd_mknotpresent(pmd)));
#endif
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static void __init pud_thp_tests(unsigned long pfn, pgprot_t prot)
{
	pud_t pud;

	/*
	 * pud_trans_huge() and pud_present() must return negative
	 * after MMU invalidation with pud_mknotpresent().
	 */
	pud = pfn_pud(pfn, prot);
	WARN_ON(!pud_trans_huge(pud_mkhuge(pud)));
	WARN_ON(pud_trans_huge(pud_mknotpresent(pud)));
	WARN_ON(pud_present(pud_mknotpresent(pud)));
}
#else
static void __init pud_thp_tests(unsigned long pfn, pgprot_t prot) { }
#endif
#else
static void __init pmd_thp_tests(unsigned long pfn, pgprot_t prot) { }
static void __init pud_thp_tests(unsigned long pfn, pgprot_t prot) { }
#endif

static unsigned long __init get_random_vaddr(void)
{
	unsigned long random_vaddr, random_pages, total_user_pages;

	total_user_pages = (TASK_SIZE - FIRST_USER_ADDRESS) / PAGE_SIZE;

	random_pages = get_random_long() % total_user_pages;
	random_vaddr = FIRST_USER_ADDRESS + random_pages * PAGE_SIZE;

	return random_vaddr;
}

void __init debug_vm_pgtable(void)
{
	struct mm_struct *mm;
	struct page *page;
	pgd_t *pgdp;
	p4d_t *p4dp, *saved_p4dp;
	pud_t *pudp, *saved_pudp;
	pmd_t *pmdp, *saved_pmdp, pmd;
	pte_t *ptep;
	pgtable_t saved_ptep;
	pgprot_t prot, protnone;
	phys_addr_t paddr;
	unsigned long vaddr, pte_aligned, pmd_aligned;
	unsigned long pud_aligned, p4d_aligned, pgd_aligned;

	pr_info("Validating architecture page table helpers\n");
	prot = vm_get_page_prot(VMFLAGS);
	vaddr = get_random_vaddr();
	mm = mm_alloc();
	if (!mm) {
		pr_err("mm_struct allocation failed\n");
		return;
	}

	/*
	 * swap_migration_tests() requires a dedicated page as it needs to
	 * be locked before creating a migration entry from it. Locking the
	 * page that actually maps kernel text ('start_kernel') can be real
	 * problematic. Lets allocate a dedicated page explicitly for this
	 * purpose that will be freed later.
	 */
	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("page allocation failed\n");
		return;
	}

	/*
	 * __P000 (or even __S000) will help create page table entries with
	 * PROT_NONE permission as required for pxx_protnone_tests().
	 */
	protnone = __P000;

	/*
	 * PFN for mapping at PTE level is determined from a standard kernel
	 * text symbol. But pfns for higher page table levels are derived by
	 * masking lower bits of this real pfn. These derived pfns might not
	 * exist on the platform but that does not really matter as pfn_pxx()
	 * helpers will still create appropriate entries for the test. This
	 * helps avoid large memory block allocations to be used for mapping
	 * at higher page table levels.
	 */
	paddr = __pa(&start_kernel);

	pte_aligned = (paddr & PAGE_MASK) >> PAGE_SHIFT;
	pmd_aligned = (paddr & PMD_MASK) >> PAGE_SHIFT;
	pud_aligned = (paddr & PUD_MASK) >> PAGE_SHIFT;
	p4d_aligned = (paddr & P4D_MASK) >> PAGE_SHIFT;
	pgd_aligned = (paddr & PGDIR_MASK) >> PAGE_SHIFT;
	WARN_ON(!pfn_valid(pte_aligned));

	pgdp = pgd_offset(mm, vaddr);
	p4dp = p4d_alloc(mm, pgdp, vaddr);
	pudp = pud_alloc(mm, p4dp, vaddr);
	pmdp = pmd_alloc(mm, pudp, vaddr);
	ptep = pte_alloc_map(mm, pmdp, vaddr);

	/*
	 * Save all the page table page addresses as the page table
	 * entries will be used for testing with random or garbage
	 * values. These saved addresses will be used for freeing
	 * page table pages.
	 */
	pmd = READ_ONCE(*pmdp);
	saved_p4dp = p4d_offset(pgdp, 0UL);
	saved_pudp = pud_offset(p4dp, 0UL);
	saved_pmdp = pmd_offset(pudp, 0UL);
	saved_ptep = pmd_pgtable(pmd);

	pte_basic_tests(pte_aligned, prot);
	pmd_basic_tests(pmd_aligned, prot);
	pud_basic_tests(pud_aligned, prot);
	p4d_basic_tests(p4d_aligned, prot);
	pgd_basic_tests(pgd_aligned, prot);

	pte_clear_tests(mm, ptep);
	pmd_clear_tests(mm, pmdp);
	pud_clear_tests(mm, pudp);
	p4d_clear_tests(mm, p4dp);
	pgd_clear_tests(mm, pgdp);

	pte_unmap(ptep);

	pmd_populate_tests(mm, pmdp, saved_ptep);
	pud_populate_tests(mm, pudp, saved_pmdp);
	p4d_populate_tests(mm, p4dp, saved_pudp);
	pgd_populate_tests(mm, pgdp, saved_p4dp);

	pte_special_tests(pte_aligned, prot);
	pte_protnone_tests(pte_aligned, protnone);
	pmd_protnone_tests(pmd_aligned, protnone);

	pte_devmap_tests(pte_aligned, prot);
	pmd_devmap_tests(pmd_aligned, prot);
	pud_devmap_tests(pud_aligned, prot);

	pte_soft_dirty_tests(pte_aligned, prot);
	pmd_soft_dirty_tests(pmd_aligned, prot);
	pte_swap_soft_dirty_tests(pte_aligned, prot);
	pmd_swap_soft_dirty_tests(pmd_aligned, prot);

	pte_swap_tests(pte_aligned, prot);
	pmd_swap_tests(pmd_aligned, prot);

	swap_migration_tests(page);
	hugetlb_tests(pte_aligned, prot);

	pmd_thp_tests(pmd_aligned, prot);
	pud_thp_tests(pud_aligned, prot);

	p4d_free(mm, saved_p4dp);
	pud_free(mm, saved_pudp);
	pmd_free(mm, saved_pmdp);
	pte_free(mm, saved_ptep);

	__free_page(page);
	mm_dec_nr_puds(mm);
	mm_dec_nr_pmds(mm);
	mm_dec_nr_ptes(mm);
	mmdrop(mm);
}
