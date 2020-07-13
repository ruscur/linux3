// SPDX-License-Identifier: GPL-2.0-only
/*
 * powerpc code to implement the kexec_file_load syscall
 *
 * Copyright (C) 2004  Adam Litke (agl@us.ibm.com)
 * Copyright (C) 2004  IBM Corp.
 * Copyright (C) 2004,2005  Milton D Miller II, IBM Corporation
 * Copyright (C) 2005  R Sharada (sharada@in.ibm.com)
 * Copyright (C) 2006  Mohan Kumar M (mohan@in.ibm.com)
 * Copyright (C) 2020  IBM Corporation
 *
 * Based on kexec-tools' kexec-ppc64.c, fs2dt.c.
 * Heavily modified for the kernel by
 * Hari Bathini <hbathini@linux.ibm.com>.
 */

#include <linux/kexec.h>
#include <linux/of_device.h>
#include <linux/slab.h>
#include <asm/sections.h>
#include <asm/kexec_ranges.h>

/**
 * get_max_nr_ranges - Get the max no. of ranges crash_mem structure
 *                     could hold, given the size allocated for it.
 * @size:              Allocation size of crash_mem structure.
 *
 * Returns the maximum no. of ranges.
 */
static inline unsigned int get_max_nr_ranges(size_t size)
{
	return ((size - sizeof(struct crash_mem)) /
		sizeof(struct crash_mem_range));
}

/**
 * get_mem_rngs_size - Get the allocated size of mrngs based on
 *                     max_nr_ranges and chunk size.
 * @mrngs:             Memory ranges.
 *
 * Returns the maximum no. of ranges.
 */
static inline size_t get_mem_rngs_size(struct crash_mem *mrngs)
{
	size_t size;

	if (!mrngs)
		return 0;

	size = (sizeof(struct crash_mem) +
		(mrngs->max_nr_ranges * sizeof(struct crash_mem_range)));

	/*
	 * Memory is allocated in size multiple of MEM_RANGE_CHUNK_SZ.
	 * So, align to get the actual length.
	 */
	return ALIGN(size, MEM_RANGE_CHUNK_SZ);
}

/**
 * __add_mem_range - add a memory range to memory ranges list.
 * @mem_ranges:      Range list to add the memory range to.
 * @base:            Base address of the range to add.
 * @size:            Size of the memory range to add.
 *
 * (Re)allocates memory, if needed.
 *
 * Returns 0 on success, negative errno on error.
 */
static int __add_mem_range(struct crash_mem **mem_ranges, u64 base, u64 size)
{
	struct crash_mem *mrngs = *mem_ranges;

	if ((mrngs == NULL) || (mrngs->nr_ranges == mrngs->max_nr_ranges)) {
		mrngs = realloc_mem_ranges(mem_ranges);
		if (!mrngs)
			return -ENOMEM;
	}

	mrngs->ranges[mrngs->nr_ranges].start = base;
	mrngs->ranges[mrngs->nr_ranges].end = base + size - 1;
	mrngs->nr_ranges++;
	return 0;
}

/**
 * __merge_memory_ranges - Merges the given memory ranges list.
 * @mem_ranges:            Range list to merge.
 *
 * Assumes a sorted range list.
 *
 * Returns nothing.
 */
static void __merge_memory_ranges(struct crash_mem *mrngs)
{
	struct crash_mem_range *rngs;
	int i, idx;

	if (!mrngs)
		return;

	idx = 0;
	rngs = &mrngs->ranges[0];
	for (i = 1; i < mrngs->nr_ranges; i++) {
		if (rngs[i].start <= (rngs[i-1].end + 1))
			rngs[idx].end = rngs[i].end;
		else {
			idx++;
			if (i == idx)
				continue;

			rngs[idx] = rngs[i];
		}
	}
	mrngs->nr_ranges = idx + 1;
}

/**
 * realloc_mem_ranges - reallocate mem_ranges with size incremented
 *                      by MEM_RANGE_CHUNK_SZ. Frees up the old memory,
 *                      if memory allocation fails.
 * @mem_ranges:         Memory ranges to reallocate.
 *
 * Returns pointer to reallocated memory on success, NULL otherwise.
 */
struct crash_mem *realloc_mem_ranges(struct crash_mem **mem_ranges)
{
	struct crash_mem *mrngs = *mem_ranges;
	unsigned int nr_ranges;
	size_t size;

	size = get_mem_rngs_size(mrngs);
	nr_ranges = mrngs ? mrngs->nr_ranges : 0;

	size += MEM_RANGE_CHUNK_SZ;
	mrngs = krealloc(*mem_ranges, size, GFP_KERNEL);
	if (!mrngs) {
		kfree(*mem_ranges);
		*mem_ranges = NULL;
		return NULL;
	}

	mrngs->nr_ranges = nr_ranges;
	mrngs->max_nr_ranges = get_max_nr_ranges(size);
	*mem_ranges = mrngs;

	return mrngs;
}

/**
 * add_mem_range - Updates existing memory range, if there is an overlap.
 *                 Else, adds a new memory range.
 * @mem_ranges:    Range list to add the memory range to.
 * @base:          Base address of the range to add.
 * @size:          Size of the memory range to add.
 *
 * (Re)allocates memory, if needed.
 *
 * Returns 0 on success, negative errno on error.
 */
int add_mem_range(struct crash_mem **mem_ranges, u64 base, u64 size)
{
	struct crash_mem *mrngs = *mem_ranges;
	u64 mstart, mend, end;
	unsigned int i;

	if (!size)
		return 0;

	end = base + size - 1;

	if ((mrngs == NULL) || (mrngs->nr_ranges == 0))
		return __add_mem_range(mem_ranges, base, size);

	for (i = 0; i < mrngs->nr_ranges; i++) {
		mstart = mrngs->ranges[i].start;
		mend = mrngs->ranges[i].end;
		if (base < mend && end > mstart) {
			if (base < mstart)
				mrngs->ranges[i].start = base;
			if (end > mend)
				mrngs->ranges[i].end = end;
			return 0;
		}
	}

	return __add_mem_range(mem_ranges, base, size);
}

/**
 * add_tce_mem_ranges - Adds tce-table range to the given memory ranges list.
 * @mem_ranges:         Range list to add the memory range(s) to.
 *
 * Returns 0 on success, negative errno on error.
 */
int add_tce_mem_ranges(struct crash_mem **mem_ranges)
{
	struct device_node *dn;
	int ret;

	for_each_node_by_type(dn, "pci") {
		u64 base;
		u32 size;

		ret = of_property_read_u64(dn, "linux,tce-base", &base);
		ret |= of_property_read_u32(dn, "linux,tce-size", &size);
		if (!ret)
			continue;

		ret = add_mem_range(mem_ranges, base, size);
		if (ret)
			break;
	}

	return ret;
}

/**
 * add_initrd_mem_range - Adds initrd range to the given memory ranges list,
 *                        if the initrd was retained.
 * @mem_ranges:           Range list to add the memory range to.
 *
 * Returns 0 on success, negative errno on error.
 */
int add_initrd_mem_range(struct crash_mem **mem_ranges)
{
	u64 base, end;
	int ret = 0;
	char *str;

	/* This range means something only if initrd was retained */
	str = strstr(saved_command_line, "retain_initrd");
	if (!str)
		return 0;

	ret = of_property_read_u64(of_chosen, "linux,initrd-start", &base);
	ret |= of_property_read_u64(of_chosen, "linux,initrd-end", &end);
	if (!ret)
		ret = add_mem_range(mem_ranges, base, end - base + 1);
	return ret;
}

/**
 * add_htab_mem_range - Adds htab range to the given memory ranges list,
 *                      if it exists
 * @mem_ranges:         Range list to add the memory range to.
 *
 * Returns 0 on success, negative errno on error.
 */
int add_htab_mem_range(struct crash_mem **mem_ranges)
{
#ifdef CONFIG_PPC_BOOK3S_64
	int ret;

	if (!htab_address)
		return 0;

	ret = add_mem_range(mem_ranges, __pa(htab_address), htab_size_bytes);
	return ret;
#else
	return 0;
#endif
}

/**
 * add_kernel_mem_range - Adds kernel text region to the given
 *                        memory ranges list.
 * @mem_ranges:           Range list to add the memory range to.
 *
 * Returns 0 on success, negative errno on error.
 */
int add_kernel_mem_range(struct crash_mem **mem_ranges)
{
	int ret;

	ret = add_mem_range(mem_ranges, 0, __pa(_end));
	return ret;
}

/**
 * add_rtas_mem_range - Adds RTAS region to the given memory ranges list.
 * @mem_ranges:         Range list to add the memory range to.
 *
 * Returns 0 on success, negative errno on error.
 */
int add_rtas_mem_range(struct crash_mem **mem_ranges)
{
	struct device_node *dn;
	int ret = 0;

	dn = of_find_node_by_path("/rtas");
	if (dn) {
		u32 base, size;

		ret = of_property_read_u32(dn, "linux,rtas-base", &base);
		ret |= of_property_read_u32(dn, "rtas-size", &size);
		if (ret)
			return ret;

		ret = add_mem_range(mem_ranges, base, size);
	}
	return ret;
}

/**
 * add_opal_mem_range - Adds OPAL region to the given memory ranges list.
 * @mem_ranges:         Range list to add the memory range to.
 *
 * Returns 0 on success, negative errno on error.
 */
int add_opal_mem_range(struct crash_mem **mem_ranges)
{
	struct device_node *dn;
	int ret = 0;

	dn = of_find_node_by_path("/ibm,opal");
	if (dn) {
		u64 base, size;

		ret = of_property_read_u64(dn, "opal-base-address", &base);
		ret |= of_property_read_u64(dn, "opal-runtime-size", &size);
		if (ret)
			return ret;

		ret = add_mem_range(mem_ranges, base, size);
	}
	return ret;
}

/**
 * add_reserved_ranges - Adds "/reserved-ranges" regions exported by f/w
 *                       to the given memory ranges list.
 * @mem_ranges:          Range list to add the memory ranges to.
 *
 * Returns 0 on success, negative errno on error.
 */
int add_reserved_ranges(struct crash_mem **mem_ranges)
{
	int i, len, ret = 0;
	const __be32 *prop;

	prop = of_get_property(of_root, "reserved-ranges", &len);
	if (!prop)
		return 0;

	/*
	 * Each reserved range is an (address,size) pair, 2 cells each,
	 * totalling 4 cells per range.
	 */
	for (i = 0; i < len / (sizeof(*prop) * 4); i++) {
		u64 base, size;

		base = of_read_number(prop + (i * 4) + 0, 2);
		size = of_read_number(prop + (i * 4) + 2, 2);

		ret = add_mem_range(mem_ranges, base, size);
		if (ret)
			break;
	}

	return ret;
}

/**
 * sort_memory_ranges - Sorts the given memory ranges list.
 * @mem_ranges:         Range list to sort.
 * @merge:              If true, merge the list after sorting.
 *
 * Returns nothing.
 */
void sort_memory_ranges(struct crash_mem *mrngs, bool merge)
{
	struct crash_mem_range *rngs;
	struct crash_mem_range rng;
	int i, j, idx;

	if (!mrngs)
		return;

	/* Sort the ranges in-place */
	rngs = &mrngs->ranges[0];
	for (i = 0; i < mrngs->nr_ranges; i++) {
		idx = i;
		for (j = (i + 1); j < mrngs->nr_ranges; j++) {
			if (rngs[idx].start > rngs[j].start)
				idx = j;
		}
		if (idx != i) {
			rng = rngs[idx];
			rngs[idx] = rngs[i];
			rngs[i] = rng;
		}
	}

	if (merge)
		__merge_memory_ranges(mrngs);
}
