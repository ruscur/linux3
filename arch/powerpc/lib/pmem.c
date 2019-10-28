// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2017 IBM Corporation. All rights reserved.
 */

#include <linux/string.h>
#include <linux/export.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>

/*
 * CONFIG_ARCH_HAS_PMEM_API symbols
 */
void arch_wb_cache_pmem(void *addr, size_t size)
{
	unsigned long start = (unsigned long) addr;
	flush_dcache_range(start, start + size);
}
EXPORT_SYMBOL_GPL(arch_wb_cache_pmem);

void arch_invalidate_pmem(void *addr, size_t size)
{
	unsigned long start = (unsigned long) addr;
	flush_dcache_range(start, start + size);
}
EXPORT_SYMBOL_GPL(arch_invalidate_pmem);

unsigned long arch_validate_namespace_size(unsigned int ndr_mappings, unsigned long size)
{
	u32 remainder;
	unsigned long linear_map_size;

	if (radix_enabled())
		linear_map_size = PAGE_SIZE;
	else
		linear_map_size = (1UL << mmu_psize_defs[mmu_linear_psize].shift);

	div_u64_rem(size, linear_map_size * ndr_mappings, &remainder);
	if (remainder)
		return linear_map_size * ndr_mappings;
	return 0;
}
EXPORT_SYMBOL_GPL(arch_validate_namespace_size);

/*
 * CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE symbols
 */
long __copy_from_user_flushcache(void *dest, const void __user *src,
		unsigned size)
{
	unsigned long copied, start = (unsigned long) dest;

	copied = __copy_from_user(dest, src, size);
	flush_dcache_range(start, start + size);

	return copied;
}

void *memcpy_flushcache(void *dest, const void *src, size_t size)
{
	unsigned long start = (unsigned long) dest;

	memcpy(dest, src, size);
	flush_dcache_range(start, start + size);

	return dest;
}
EXPORT_SYMBOL(memcpy_flushcache);

void memcpy_page_flushcache(char *to, struct page *page, size_t offset,
	size_t len)
{
	memcpy_flushcache(to, page_to_virt(page) + offset, len);
}
EXPORT_SYMBOL(memcpy_page_flushcache);
