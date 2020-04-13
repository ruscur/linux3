// SPDX-License-Identifier: GPL-2.0
/*
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/export.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

#ifdef CONFIG_HAVE_ARCH_HUGE_VMAP
static int __read_mostly ioremap_p4d_capable;
static int __read_mostly ioremap_pud_capable;
static int __read_mostly ioremap_pmd_capable;
static int __read_mostly ioremap_huge_disabled;

static int __init set_nohugeiomap(char *str)
{
	ioremap_huge_disabled = 1;
	return 0;
}
early_param("nohugeiomap", set_nohugeiomap);

void __init ioremap_huge_init(void)
{
	if (!ioremap_huge_disabled) {
		if (arch_ioremap_p4d_supported())
			ioremap_p4d_capable = 1;
		if (arch_ioremap_pud_supported())
			ioremap_pud_capable = 1;
		if (arch_ioremap_pmd_supported())
			ioremap_pmd_capable = 1;
	}
}

static inline int ioremap_p4d_enabled(void)
{
	return ioremap_p4d_capable;
}

static inline int ioremap_pud_enabled(void)
{
	return ioremap_pud_capable;
}

static inline int ioremap_pmd_enabled(void)
{
	return ioremap_pmd_capable;
}

#else	/* !CONFIG_HAVE_ARCH_HUGE_VMAP */
static inline int ioremap_p4d_enabled(void) { return 0; }
static inline int ioremap_pud_enabled(void) { return 0; }
static inline int ioremap_pmd_enabled(void) { return 0; }
#endif	/* CONFIG_HAVE_ARCH_HUGE_VMAP */

int ioremap_page_range(unsigned long addr,
		       unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	unsigned int max_page_shift = PAGE_SHIFT;

	/*
	 * Due to the max_page_shift parameter to vmap_range, platforms must
	 * enable all smaller sizes to take advantage of a given size,
	 * otherwise fall back to small pages.
	 */
	if (ioremap_pmd_enabled()) {
		max_page_shift = PMD_SHIFT;
		if (ioremap_pud_enabled()) {
			max_page_shift = PUD_SHIFT;
			if (ioremap_p4d_enabled())
				max_page_shift = P4D_SHIFT;
		}
	}

	return vmap_range(addr, end, phys_addr, prot, max_page_shift);
}

#ifdef CONFIG_GENERIC_IOREMAP
void __iomem *ioremap_prot(phys_addr_t addr, size_t size, unsigned long prot)
{
	unsigned long offset, vaddr;
	phys_addr_t last_addr;
	struct vm_struct *area;

	/* Disallow wrap-around or zero size */
	last_addr = addr + size - 1;
	if (!size || last_addr < addr)
		return NULL;

	/* Page-align mappings */
	offset = addr & (~PAGE_MASK);
	addr -= offset;
	size = PAGE_ALIGN(size + offset);

	area = get_vm_area_caller(size, VM_IOREMAP,
			__builtin_return_address(0));
	if (!area)
		return NULL;
	vaddr = (unsigned long)area->addr;

	if (ioremap_page_range(vaddr, vaddr + size, addr, __pgprot(prot))) {
		free_vm_area(area);
		return NULL;
	}

	return (void __iomem *)(vaddr + offset);
}
EXPORT_SYMBOL(ioremap_prot);

void iounmap(volatile void __iomem *addr)
{
	vunmap((void *)((unsigned long)addr & PAGE_MASK));
}
EXPORT_SYMBOL(iounmap);
#endif /* CONFIG_GENERIC_IOREMAP */
