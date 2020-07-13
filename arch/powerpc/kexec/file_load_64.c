// SPDX-License-Identifier: GPL-2.0-only
/*
 * ppc64 code to implement the kexec_file_load syscall
 *
 * Copyright (C) 2004  Adam Litke (agl@us.ibm.com)
 * Copyright (C) 2004  IBM Corp.
 * Copyright (C) 2004,2005  Milton D Miller II, IBM Corporation
 * Copyright (C) 2005  R Sharada (sharada@in.ibm.com)
 * Copyright (C) 2006  Mohan Kumar M (mohan@in.ibm.com)
 * Copyright (C) 2020  IBM Corporation
 *
 * Based on kexec-tools' kexec-ppc64.c, kexec-elf-rel-ppc64.c, fs2dt.c.
 * Heavily modified for the kernel by
 * Hari Bathini <hbathini@linux.ibm.com>.
 */

#include <linux/kexec.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>
#include <linux/of_device.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/types.h>
#include <asm/drmem.h>
#include <asm/kexec_ranges.h>
#include <asm/crashdump-ppc64.h>

struct umem_info {
	uint64_t *buf; /* data buffer for usable-memory property */
	uint32_t idx;  /* current index */
	uint32_t size; /* size allocated for the data buffer */

	/* usable memory ranges to look up */
	const struct crash_mem *umrngs;
};

const struct kexec_file_ops * const kexec_file_loaders[] = {
	&kexec_elf64_ops,
	NULL
};

/**
 * get_exclude_memory_ranges - Get exclude memory ranges. This list includes
 *                             regions like opal/rtas, tce-table, initrd,
 *                             kernel, htab which should be avoided while
 *                             setting up kexec load segments.
 * @mem_ranges:                Range list to add the memory ranges to.
 *
 * Returns 0 on success, negative errno on error.
 */
static int get_exclude_memory_ranges(struct crash_mem **mem_ranges)
{
	int ret;

	ret = add_tce_mem_ranges(mem_ranges);
	if (ret)
		goto out;

	ret = add_initrd_mem_range(mem_ranges);
	if (ret)
		goto out;

	ret = add_htab_mem_range(mem_ranges);
	if (ret)
		goto out;

	ret = add_kernel_mem_range(mem_ranges);
	if (ret)
		goto out;

	ret = add_rtas_mem_range(mem_ranges);
	if (ret)
		goto out;

	ret = add_opal_mem_range(mem_ranges);
	if (ret)
		goto out;

	ret = add_reserved_ranges(mem_ranges);
	if (ret)
		goto out;

	/* exclude memory ranges should be sorted for easy lookup */
	sort_memory_ranges(*mem_ranges, true);
out:
	if (ret)
		pr_err("Failed to setup exclude memory ranges\n");
	return ret;
}

/**
 * get_usable_memory_ranges - Get usable memory ranges. This list includes
 *                            regions like crashkernel, opal/rtas & tce-table,
 *                            that kdump kernel could use.
 * @mem_ranges:               Range list to add the memory ranges to.
 *
 * Returns 0 on success, negative errno on error.
 */
static int get_usable_memory_ranges(struct crash_mem **mem_ranges)
{
	int ret;

	/* First memory block & crashkernel region */
	ret = add_mem_range(mem_ranges, 0, crashk_res.end + 1);
	if (ret)
		goto out;

	ret = add_rtas_mem_range(mem_ranges);
	if (ret)
		goto out;

	ret = add_opal_mem_range(mem_ranges);
	if (ret)
		goto out;

	ret = add_tce_mem_ranges(mem_ranges);
out:
	if (ret)
		pr_err("Failed to setup usable memory ranges\n");
	return ret;
}

/**
 * __locate_mem_hole_top_down - Looks top down for a large enough memory hole
 *                              in the memory regions between buf_min & buf_max
 *                              for the buffer. If found, sets kbuf->mem.
 * @kbuf:                       Buffer contents and memory parameters.
 * @buf_min:                    Minimum address for the buffer.
 * @buf_max:                    Maximum address for the buffer.
 *
 * Returns 0 on success, negative errno on error.
 */
static int __locate_mem_hole_top_down(struct kexec_buf *kbuf,
				      u64 buf_min, u64 buf_max)
{
	int ret = -EADDRNOTAVAIL;
	phys_addr_t start, end;
	u64 i;

	for_each_mem_range_rev(i, &memblock.memory, NULL, NUMA_NO_NODE,
			       MEMBLOCK_NONE, &start, &end, NULL) {
		if (start > buf_max)
			continue;

		/* Memory hole not found */
		if (end < buf_min)
			break;

		/* Adjust memory region based on the given range */
		if (start < buf_min)
			start = buf_min;
		if (end > buf_max)
			end = buf_max;

		start = ALIGN(start, kbuf->buf_align);
		if (start < end && (end - start + 1) >= kbuf->memsz) {
			/* Suitable memory range found. Set kbuf->mem */
			kbuf->mem = ALIGN_DOWN(end - kbuf->memsz + 1,
					       kbuf->buf_align);
			ret = 0;
			break;
		}
	}

	return ret;
}

/**
 * locate_mem_hole_top_down_ppc64 - Skip special memory regions to find a
 *                                  suitable buffer with top down approach.
 * @kbuf:                           Buffer contents and memory parameters.
 * @buf_min:                        Minimum address for the buffer.
 * @buf_max:                        Maximum address for the buffer.
 * @emem:                           Exclude memory ranges.
 *
 * Returns 0 on success, negative errno on error.
 */
static int locate_mem_hole_top_down_ppc64(struct kexec_buf *kbuf,
					  u64 buf_min, u64 buf_max,
					  const struct crash_mem *emem)
{
	int i, ret = 0, err = -EADDRNOTAVAIL;
	u64 start, end, tmin, tmax;

	tmax = buf_max;
	for (i = (emem->nr_ranges - 1); i >= 0; i--) {
		start = emem->ranges[i].start;
		end = emem->ranges[i].end;

		if (start > tmax)
			continue;

		if (end < tmax) {
			tmin = (end < buf_min ? buf_min : end + 1);
			ret = __locate_mem_hole_top_down(kbuf, tmin, tmax);
			if (!ret)
				return 0;
		}

		tmax = start - 1;

		if (tmax < buf_min) {
			ret = err;
			break;
		}
		ret = 0;
	}

	if (!ret) {
		tmin = buf_min;
		ret = __locate_mem_hole_top_down(kbuf, tmin, tmax);
	}
	return ret;
}

/**
 * __locate_mem_hole_bottom_up - Looks bottom up for a large enough memory hole
 *                               in the memory regions between buf_min & buf_max
 *                               for the buffer. If found, sets kbuf->mem.
 * @kbuf:                        Buffer contents and memory parameters.
 * @buf_min:                     Minimum address for the buffer.
 * @buf_max:                     Maximum address for the buffer.
 *
 * Returns 0 on success, negative errno on error.
 */
static int __locate_mem_hole_bottom_up(struct kexec_buf *kbuf,
				       u64 buf_min, u64 buf_max)
{
	int ret = -EADDRNOTAVAIL;
	phys_addr_t start, end;
	u64 i;

	for_each_mem_range(i, &memblock.memory, NULL, NUMA_NO_NODE,
			   MEMBLOCK_NONE, &start, &end, NULL) {
		if (end < buf_min)
			continue;

		/* Memory hole not found */
		if (start > buf_max)
			break;

		/* Adjust memory region based on the given range */
		if (start < buf_min)
			start = buf_min;
		if (end > buf_max)
			end = buf_max;

		start = ALIGN(start, kbuf->buf_align);
		if (start < end && (end - start + 1) >= kbuf->memsz) {
			/* Suitable memory range found. Set kbuf->mem */
			kbuf->mem = start;
			ret = 0;
			break;
		}
	}

	return ret;
}

/**
 * locate_mem_hole_bottom_up_ppc64 - Skip special memory regions to find a
 *                                   suitable buffer with bottom up approach.
 * @kbuf:                            Buffer contents and memory parameters.
 * @buf_min:                         Minimum address for the buffer.
 * @buf_max:                         Maximum address for the buffer.
 * @emem:                            Exclude memory ranges.
 *
 * Returns 0 on success, negative errno on error.
 */
static int locate_mem_hole_bottom_up_ppc64(struct kexec_buf *kbuf,
					   u64 buf_min, u64 buf_max,
					   const struct crash_mem *emem)
{
	int i, ret = 0, err = -EADDRNOTAVAIL;
	u64 start, end, tmin, tmax;

	tmin = buf_min;
	for (i = 0; i < emem->nr_ranges; i++) {
		start = emem->ranges[i].start;
		end = emem->ranges[i].end;

		if (end < tmin)
			continue;

		if (start > tmin) {
			tmax = (start > buf_max ? buf_max : start - 1);
			ret = __locate_mem_hole_bottom_up(kbuf, tmin, tmax);
			if (!ret)
				return 0;
		}

		tmin = end + 1;

		if (tmin > buf_max) {
			ret = err;
			break;
		}
		ret = 0;
	}

	if (!ret) {
		tmax = buf_max;
		ret = __locate_mem_hole_bottom_up(kbuf, tmin, tmax);
	}
	return ret;
}

/**
 * check_realloc_usable_mem - Reallocate buffer if it can't accommodate entries
 * @um_info:                  Usable memory buffer and ranges info.
 * @cnt:                      No. of entries to accommodate.
 *
 * Returns 0 on success, negative errno on error.
 */
static uint64_t *check_realloc_usable_mem(struct umem_info *um_info, int cnt)
{
	void *tbuf;

	if (um_info->size >=
	    ((um_info->idx + cnt) * sizeof(*(um_info->buf))))
		return um_info->buf;

	um_info->size += MEM_RANGE_CHUNK_SZ;
	tbuf = krealloc(um_info->buf, um_info->size, GFP_KERNEL);
	if (!tbuf) {
		um_info->size -= MEM_RANGE_CHUNK_SZ;
		return NULL;
	}

	memset(tbuf + um_info->idx, 0, MEM_RANGE_CHUNK_SZ);
	return tbuf;
}

/**
 * add_usable_mem - Add the usable memory ranges within the given memory range
 *                  to the buffer
 * @um_info:        Usable memory buffer and ranges info.
 * @base:           Base address of memory range to look for.
 * @end:            End address of memory range to look for.
 * @cnt:            No. of usable memory ranges added to buffer.
 *
 * Returns 0 on success, negative errno on error.
 */
static int add_usable_mem(struct umem_info *um_info, uint64_t base,
			  uint64_t end, int *cnt)
{
	uint64_t loc_base, loc_end, *buf;
	const struct crash_mem *umrngs;
	int i, add;

	*cnt = 0;
	umrngs = um_info->umrngs;
	for (i = 0; i < umrngs->nr_ranges; i++) {
		add = 0;
		loc_base = umrngs->ranges[i].start;
		loc_end = umrngs->ranges[i].end;
		if (loc_base >= base && loc_end <= end)
			add = 1;
		else if (base < loc_end && end > loc_base) {
			if (loc_base < base)
				loc_base = base;
			if (loc_end > end)
				loc_end = end;
			add = 1;
		}

		if (add) {
			buf = check_realloc_usable_mem(um_info, 2);
			if (!buf)
				return -ENOMEM;

			um_info->buf = buf;
			buf[um_info->idx++] = cpu_to_be64(loc_base);
			buf[um_info->idx++] =
					cpu_to_be64(loc_end - loc_base + 1);
			(*cnt)++;
		}
	}

	return 0;
}

/**
 * kdump_setup_usable_lmb - This is a callback function that gets called by
 *                          walk_drmem_lmbs for every LMB to set its
 *                          usable memory ranges.
 * @lmb:                    LMB info.
 * @usm:                    linux,drconf-usable-memory property value.
 * @data:                   Pointer to usable memory buffer and ranges info.
 *
 * Returns 0 on success, negative errno on error.
 */
static int kdump_setup_usable_lmb(struct drmem_lmb *lmb, const __be32 **usm,
				  void *data)
{
	struct umem_info *um_info;
	uint64_t base, end, *buf;
	int cnt, tmp_idx, ret;

	/*
	 * kdump load isn't supported on kernels already booted with
	 * linux,drconf-usable-memory property.
	 */
	if (*usm) {
		pr_err("Trying kdump load from a kdump kernel?\n");
		return -EINVAL;
	}

	um_info = data;
	tmp_idx = um_info->idx;
	buf = check_realloc_usable_mem(um_info, 1);
	if (!buf)
		return -ENOMEM;

	um_info->idx++;
	um_info->buf = buf;
	base = lmb->base_addr;
	end = base + drmem_lmb_size() - 1;
	ret = add_usable_mem(um_info, base, end, &cnt);
	if (!ret)
		um_info->buf[tmp_idx] = cpu_to_be64(cnt);

	return ret;
}

/**
 * get_node_path - Get the full path of the given node.
 * @dn:            Node.
 * @path:          Updated with the full path of the node.
 *
 * Returns nothing.
 */
static void get_node_path(struct device_node *dn, char *path)
{
	if (!dn)
		return;

	get_node_path(dn->parent, path);
	sprintf(path, "/%s", dn->full_name);
}

/**
 * get_node_pathlen - Get the full path length of the given node.
 * @dn:               Node.
 *
 * Returns the length of the full path of the node.
 */
static int get_node_pathlen(struct device_node *dn)
{
	int len = 0;

	while (dn) {
		len += strlen(dn->full_name) + 1;
		dn = dn->parent;
	}
	len++;

	return len;
}

/**
 * add_usable_mem_property - Add usable memory property for the given
 *                           memory node.
 * @fdt:                     Flattened device tree for the kdump kernel.
 * @dn:                      Memory node.
 * @um_info:                 Usable memory buffer and ranges info.
 *
 * Returns 0 on success, negative errno on error.
 */
static int add_usable_mem_property(void *fdt, struct device_node *dn,
				   struct umem_info *um_info)
{
	int n_mem_addr_cells, n_mem_size_cells, node;
	int i, len, ranges, cnt, ret;
	uint64_t base, end, *buf;
	const __be32 *prop;
	char *pathname;

	/* Allocate memory for node path */
	pathname = kzalloc(ALIGN(get_node_pathlen(dn), 8), GFP_KERNEL);
	if (!pathname)
		return -ENOMEM;

	/* Get the full path of the memory node */
	get_node_path(dn, pathname);
	pr_debug("Memory node path: %s\n", pathname);

	/* Now that we know the path, find its offset in kdump kernel's fdt */
	node = fdt_path_offset(fdt, pathname);
	if (node < 0) {
		pr_err("Malformed device tree: error reading %s\n",
		       pathname);
		ret = -EINVAL;
		goto out;
	}

	/* Get the address & size cells */
	n_mem_addr_cells = of_n_addr_cells(dn);
	n_mem_size_cells = of_n_size_cells(dn);
	pr_debug("address cells: %d, size cells: %d\n", n_mem_addr_cells,
		 n_mem_size_cells);

	um_info->idx  = 0;
	buf = check_realloc_usable_mem(um_info, 2);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	um_info->buf = buf;

	prop = of_get_property(dn, "reg", &len);
	if (!prop || len <= 0) {
		ret = 0;
		goto out;
	}

	/*
	 * "reg" property represents sequence of (addr,size) duples
	 * each representing a memory range.
	 */
	ranges = (len >> 2) / (n_mem_addr_cells + n_mem_size_cells);

	for (i = 0; i < ranges; i++) {
		base = of_read_number(prop, n_mem_addr_cells);
		prop += n_mem_addr_cells;
		end = base + of_read_number(prop, n_mem_size_cells) - 1;

		ret = add_usable_mem(um_info, base, end, &cnt);
		if (ret) {
			ret = ret;
			goto out;
		}
	}

	/*
	 * No kdump kernel usable memory found in this memory node.
	 * Write (0,0) duple in linux,usable-memory property for
	 * this region to be ignored.
	 */
	if (um_info->idx == 0) {
		um_info->buf[0] = 0;
		um_info->buf[1] = 0;
		um_info->idx = 2;
	}

	ret = fdt_setprop(fdt, node, "linux,usable-memory", um_info->buf,
			  (um_info->idx * sizeof(*(um_info->buf))));

out:
	kfree(pathname);
	return ret;
}


/**
 * update_usable_mem_fdt - Updates kdump kernel's fdt with linux,usable-memory
 *                         and linux,drconf-usable-memory DT properties as
 *                         appropriate to restrict its memory usage.
 * @fdt:                   Flattened device tree for the kdump kernel.
 * @usable_mem:            Usable memory ranges for kdump kernel.
 *
 * Returns 0 on success, negative errno on error.
 */
static int update_usable_mem_fdt(void *fdt, struct crash_mem *usable_mem)
{
	struct umem_info um_info;
	struct device_node *dn;
	int node, ret = 0;

	if (!usable_mem) {
		pr_err("Usable memory ranges for kdump kernel not found\n");
		return -ENOENT;
	}

	node = fdt_path_offset(fdt, "/ibm,dynamic-reconfiguration-memory");
	if (node == -FDT_ERR_NOTFOUND)
		pr_debug("No dynamic reconfiguration memory found\n");
	else if (node < 0) {
		pr_err("Malformed device tree: error reading /ibm,dynamic-reconfiguration-memory.\n");
		return -EINVAL;
	}

	um_info.size = 0;
	um_info.idx  = 0;
	um_info.buf  = NULL;
	um_info.umrngs = usable_mem;

	dn = of_find_node_by_path("/ibm,dynamic-reconfiguration-memory");
	if (dn) {
		ret = walk_drmem_lmbs(dn, &um_info, kdump_setup_usable_lmb);
		of_node_put(dn);

		if (ret)
			goto out;

		ret = fdt_setprop(fdt, node, "linux,drconf-usable-memory",
				  um_info.buf,
				  (um_info.idx * sizeof(*(um_info.buf))));
		if (ret) {
			pr_err("Failed to set linux,drconf-usable-memory property");
			goto out;
		}
	}

	/*
	 * Walk through each memory node and set linux,usable-memory property
	 * for the corresponding node in kdump kernel's fdt.
	 */
	for_each_node_by_type(dn, "memory") {
		ret = add_usable_mem_property(fdt, dn, &um_info);
		if (ret) {
			pr_err("Failed to set linux,usable-memory property for %s node",
			       dn->full_name);
			goto out;
		}
	}

out:
	kfree(um_info.buf);
	return ret;
}

/**
 * get_toc_section - Look for ".toc" symbol and return the corresponding section
 *                   in the purgatory.
 * @pi:              Purgatory Info.
 *
 * Returns TOC section on success, NULL otherwise.
 */
static const Elf_Shdr *get_toc_section(const struct purgatory_info *pi)
{
	const Elf_Shdr *sechdrs;
	const char *secstrings;
	int i;

	if (!pi->ehdr) {
		pr_err("Purgatory elf load info missing?\n");
		return NULL;
	}

	sechdrs = (void *)pi->ehdr + pi->ehdr->e_shoff;
	secstrings = (void *)pi->ehdr + sechdrs[pi->ehdr->e_shstrndx].sh_offset;

	for (i = 0; i < pi->ehdr->e_shnum; i++) {
		if ((sechdrs[i].sh_size != 0) &&
		    (strcmp(secstrings + sechdrs[i].sh_name, ".toc") == 0)) {
			/* Return the relocated ".toc" section */
			return &(pi->sechdrs[i]);
		}
	}

	return NULL;
}

/**
 * get_toc_ptr - Get the TOC pointer (r2) of purgatory.
 * @pi:          Purgatory Info.
 *
 * Returns r2 on success, 0 otherwise.
 */
static unsigned long get_toc_ptr(const struct purgatory_info *pi)
{
	unsigned long toc_ptr = 0;
	const Elf_Shdr *sechdr;

	sechdr = get_toc_section(pi);
	if (!sechdr)
		pr_err("Could not get the TOC section!\n");
	else
		toc_ptr = sechdr->sh_addr + 0x8000;	/* 0x8000 into TOC */

	pr_debug("TOC pointer (r2) is 0x%lx\n", toc_ptr);
	return toc_ptr;
}

/* Helper functions to apply relocations */
static int do_relative_toc(unsigned long val, uint16_t *loc,
			   unsigned long mask, int complain_signed)
{
	if (complain_signed && (val + 0x8000 > 0xffff)) {
		pr_err("TOC16 relocation overflows (%lu)\n", val);
		return -ENOEXEC;
	}

	if ((~mask & 0xffff) & val) {
		pr_err("Bad TOC16 relocation (%lu)\n", val);
		return -ENOEXEC;
	}

	*loc = (*loc & ~mask) | (val & mask);
	return 0;
}
#ifdef PPC64_ELF_ABI_v2
/* PowerPC64 specific values for the Elf64_Sym st_other field.  */
#define STO_PPC64_LOCAL_BIT	5
#define STO_PPC64_LOCAL_MASK	(7 << STO_PPC64_LOCAL_BIT)
#define PPC64_LOCAL_ENTRY_OFFSET(other)					\
	(((1 << (((other) & STO_PPC64_LOCAL_MASK) >> STO_PPC64_LOCAL_BIT)) \
	 >> 2) << 2)

static unsigned int local_entry_offset(const Elf64_Sym *sym)
{
	/* If this symbol has a local entry point, use it. */
	return PPC64_LOCAL_ENTRY_OFFSET(sym->st_other);
}
#else
static unsigned int local_entry_offset(const Elf64_Sym *sym)
{
	return 0;
}
#endif

/**
 * __kexec_do_relocs - Apply relocations based on relocation type.
 * @my_r2:             TOC pointer.
 * @sym:               Symbol to relocate.
 * @r_type:            Relocation type.
 * @loc:               Location to modify.
 * @val:               Relocated symbol value.
 * @addr:              Final location after relocation.
 *
 * Returns 0 on success, negative errno on error.
 */
static int __kexec_do_relocs(unsigned long my_r2, const Elf_Sym *sym,
			     int r_type, void *loc, unsigned long val,
			     unsigned long addr)
{
	int ret = 0;

	switch (r_type) {
	case R_PPC64_ADDR32:
		/* Simply set it */
		*(uint32_t *)loc = val;
		break;

	case R_PPC64_ADDR64:
		/* Simply set it */
		*(uint64_t *)loc = val;
		break;

	case R_PPC64_REL64:
		*(uint64_t *)loc = val - (uint64_t)addr;
		break;

	case R_PPC64_REL32:
		/* Convert value to relative */
		val -= addr;
		if (val + 0x80000000 > 0xffffffff) {
			pr_err("REL32 %li out of range!\n", val);
			return -ENOEXEC;
		}

		*(uint32_t *)loc = val;
		break;

	case R_PPC64_TOC:
		*(uint64_t *)loc = my_r2;
		break;

	case R_PPC64_TOC16:
		ret = do_relative_toc(val - my_r2, loc, 0xffff, 1);
		break;

	case R_PPC64_TOC16_DS:
		ret = do_relative_toc(val - my_r2, loc, 0xfffc, 1);
		break;

	case R_PPC64_TOC16_LO:
		ret = do_relative_toc(val - my_r2, loc, 0xffff, 0);
		break;

	case R_PPC64_TOC16_LO_DS:
		ret = do_relative_toc(val - my_r2, loc, 0xfffc, 0);
		break;

	case R_PPC64_TOC16_HI:
		ret = do_relative_toc((val - my_r2) >> 16, loc,
				      0xffff, 0);
		break;

	case R_PPC64_TOC16_HA:
		ret = do_relative_toc((val - my_r2 + 0x8000) >> 16, loc,
				      0xffff, 0);
		break;

	case R_PPC64_REL24:
		val += local_entry_offset(sym);
		/* Convert value to relative */
		val -= addr;
		if (val + 0x2000000 > 0x3ffffff || (val & 3) != 0) {
			pr_err("REL24 %li out of range!\n", val);
			return -ENOEXEC;
		}

		/* Only replace bits 2 through 26 */
		*(uint32_t *)loc = ((*(uint32_t *)loc & ~0x03fffffc) |
				    (val & 0x03fffffc));
		break;

	case R_PPC64_ADDR16_LO:
		*(uint16_t *)loc = val & 0xffff;
		break;

	case R_PPC64_ADDR16_HI:
		*(uint16_t *)loc = (val >> 16) & 0xffff;
		break;

	case R_PPC64_ADDR16_HA:
		*(uint16_t *)loc = (((val + 0x8000) >> 16) & 0xffff);
		break;

	case R_PPC64_ADDR16_HIGHER:
		*(uint16_t *)loc = (((uint64_t)val >> 32) & 0xffff);
		break;

	case R_PPC64_ADDR16_HIGHEST:
		*(uint16_t *)loc = (((uint64_t)val >> 48) & 0xffff);
		break;

		/* R_PPC64_REL16_HA and R_PPC64_REL16_LO are handled to support
		 * ABIv2 r2 assignment based on r12 for PIC executable.
		 * Here address is known, so replace
		 *	0:	addis 2,12,.TOC.-0b@ha
		 *		addi 2,2,.TOC.-0b@l
		 * by
		 *		lis 2,.TOC.@ha
		 *		addi 2,2,.TOC.@l
		 */
	case R_PPC64_REL16_HA:
		/* check that we are dealing with the addis 2,12 instruction */
		if (((*(uint32_t *)loc) & 0xffff0000) != 0x3c4c0000) {
			pr_err("Unexpected instruction for  R_PPC64_REL16_HA");
			return -ENOEXEC;
		}

		val += my_r2;
		/* replacing by lis 2 */
		*(uint32_t *)loc = 0x3c400000 + ((val >> 16) & 0xffff);
		break;

	case R_PPC64_REL16_LO:
		/* check that we are dealing with the addi 2,2 instruction */
		if (((*(uint32_t *)loc) & 0xffff0000) != 0x38420000) {
			pr_err("Unexpected instruction for R_PPC64_REL16_LO");
			return -ENOEXEC;
		}

		val += my_r2 - 4;
		*(uint16_t *)loc = val & 0xffff;
		break;

	default:
		pr_err("Unknown rela relocation: %d\n", r_type);
		ret = -ENOEXEC;
		break;
	}

	return ret;
}

/**
 * load_backup_segment - Initialize backup segment of crashing kernel.
 * @image:               Kexec image.
 * @kbuf:                Buffer contents and memory parameters.
 *
 * Returns 0 on success, negative errno on error.
 */
static int load_backup_segment(struct kimage *image, struct kexec_buf *kbuf)
{
	void *buf;
	int ret;

	/* Setup a segment for backup region */
	buf = vzalloc(BACKUP_SRC_SIZE);
	if (!buf)
		return -ENOMEM;

	/*
	 * A source buffer has no meaning for backup region as data will
	 * be copied from backup source, after crash, in the purgatory.
	 * But as load segment code doesn't recognize such segments,
	 * setup a dummy source buffer to keep it happy for now.
	 */
	kbuf->buffer = buf;
	kbuf->mem = KEXEC_BUF_MEM_UNKNOWN;
	kbuf->bufsz = kbuf->memsz = BACKUP_SRC_SIZE;
	kbuf->top_down = false;

	ret = kexec_add_buffer(kbuf);
	if (ret) {
		vfree(buf);
		return ret;
	}

	image->arch.backup_buf = buf;
	image->arch.backup_start = kbuf->mem;
	return 0;
}

/**
 * load_crashdump_segments_ppc64 - Initialize the additional segements needed
 *                                 to load kdump kernel.
 * @image:                         Kexec image.
 * @kbuf:                          Buffer contents and memory parameters.
 *
 * Returns 0 on success, negative errno on error.
 */
int load_crashdump_segments_ppc64(struct kimage *image,
				  struct kexec_buf *kbuf)
{
	int ret;

	/* Load backup segment - first 64K bytes of the crashing kernel */
	ret = load_backup_segment(image, kbuf);
	if (ret) {
		pr_err("Failed to load backup segment\n");
		return ret;
	}
	pr_debug("Loaded the backup region at 0x%lx\n", kbuf->mem);

	return 0;
}

/**
 * setup_purgatory_ppc64 - initialize PPC64 specific purgatory's global
 *                         variables and call setup_purgatory() to initialize
 *                         common global variable.
 * @image:                 kexec image.
 * @slave_code:            Slave code for the purgatory.
 * @fdt:                   Flattened device tree for the next kernel.
 * @kernel_load_addr:      Address where the kernel is loaded.
 * @fdt_load_addr:         Address where the flattened device tree is loaded.
 *
 * Returns 0 on success, negative errno on error.
 */
int setup_purgatory_ppc64(struct kimage *image, const void *slave_code,
			  const void *fdt, unsigned long kernel_load_addr,
			  unsigned long fdt_load_addr)
{
	struct device_node *dn;
	void *stack_buf;
	uint64_t val;
	int ret;

	ret = setup_purgatory(image, slave_code, fdt, kernel_load_addr,
			      fdt_load_addr);
	if (ret)
		goto out;

	if (image->type == KEXEC_TYPE_CRASH) {
		uint32_t my_run_at_load = 1;

		/*
		 * Tell relocatable kernel to run at load address
		 * via the word meant for that at 0x5c.
		 */
		ret = kexec_purgatory_get_set_symbol(image, "run_at_load",
						     &my_run_at_load,
						     sizeof(my_run_at_load),
						     false);
		if (ret)
			goto out;
	}

	/* Tell purgatory where to look for backup region */
	ret = kexec_purgatory_get_set_symbol(image, "backup_start",
					     &image->arch.backup_start,
					     sizeof(image->arch.backup_start),
					     false);
	if (ret)
		goto out;

	/* Setup the stack top */
	stack_buf = kexec_purgatory_get_symbol_addr(image, "stack_buf");
	if (!stack_buf)
		goto out;

	val = (u64)stack_buf + KEXEC_PURGATORY_STACK_SIZE;
	ret = kexec_purgatory_get_set_symbol(image, "stack", &val, sizeof(val),
					     false);
	if (ret)
		goto out;

	/* Setup the TOC pointer */
	val = get_toc_ptr(&(image->purgatory_info));
	ret = kexec_purgatory_get_set_symbol(image, "my_toc", &val, sizeof(val),
					     false);
	if (ret)
		goto out;

	/* Setup OPAL base & entry values */
	dn = of_find_node_by_path("/ibm,opal");
	if (dn) {
		of_property_read_u64(dn, "opal-base-address", &val);
		ret = kexec_purgatory_get_set_symbol(image, "opal_base", &val,
						     sizeof(val), false);
		if (ret)
			goto out;

		of_property_read_u64(dn, "opal-entry-address", &val);
		ret = kexec_purgatory_get_set_symbol(image, "opal_entry", &val,
						     sizeof(val), false);
	}
out:
	if (ret)
		pr_err("Failed to setup purgatory symbols");
	return ret;
}

/**
 * setup_new_fdt_ppc64 - Update the flattend device-tree of the kernel
 *                       being loaded.
 * @image:               kexec image being loaded.
 * @fdt:                 Flattened device tree for the next kernel.
 * @initrd_load_addr:    Address where the next initrd will be loaded.
 * @initrd_len:          Size of the next initrd, or 0 if there will be none.
 * @cmdline:             Command line for the next kernel, or NULL if there will
 *                       be none.
 *
 * Returns 0 on success, negative errno on error.
 */
int setup_new_fdt_ppc64(const struct kimage *image, void *fdt,
			unsigned long initrd_load_addr,
			unsigned long initrd_len, const char *cmdline)
{
	struct crash_mem *umem = NULL;
	int chosen_node, ret;

	/* Remove memory reservation for the current device tree. */
	ret = delete_fdt_mem_rsv(fdt, __pa(initial_boot_params),
				 fdt_totalsize(initial_boot_params));
	if (ret == 0)
		pr_debug("Removed old device tree reservation.\n");
	else if (ret != -ENOENT) {
		pr_err("Failed to remove old device-tree reservation.\n");
		return ret;
	}

	/*
	 * Restrict memory usage for kdump kernel by setting up
	 * usable memory ranges and memory reserve map.
	 */
	if (image->type == KEXEC_TYPE_CRASH) {
		ret = get_usable_memory_ranges(&umem);
		if (ret)
			goto out;

		ret = update_usable_mem_fdt(fdt, umem);
		if (ret) {
			pr_err("Error setting up usable-memory property for kdump kernel\n");
			goto out;
		}

		ret = fdt_add_mem_rsv(fdt, BACKUP_SRC_START + BACKUP_SRC_SIZE,
				      crashk_res.start - BACKUP_SRC_SIZE);
		if (ret) {
			pr_err("Error reserving crash memory: %s\n",
			       fdt_strerror(ret));
			goto out;
		}
	}

	if (image->arch.backup_start) {
		ret = fdt_add_mem_rsv(fdt, image->arch.backup_start,
				      BACKUP_SRC_SIZE);
		if (ret) {
			pr_err("Error reserving memory for backup: %s\n",
			       fdt_strerror(ret));
			goto out;
		}
	}

	ret = setup_new_fdt(image, fdt, initrd_load_addr, initrd_len,
			    cmdline, &chosen_node);
	if (ret)
		goto out;

	ret = fdt_setprop(fdt, chosen_node, "linux,booted-from-kexec", NULL, 0);
	if (ret)
		pr_err("Failed to update device-tree with linux,booted-from-kexec\n");
out:
	kfree(umem);
	return ret;
}

/**
 * arch_kexec_locate_mem_hole - Skip special memory regions like rtas, opal,
 *                              tce-table, reserved-ranges & such (exclude
 *                              memory ranges) as they can't be used for kexec
 *                              segment buffer. Sets kbuf->mem when a suitable
 *                              memory hole is found.
 * @kbuf:                       Buffer contents and memory parameters.
 *
 * Assumes minimum of PAGE_SIZE alignment for kbuf->memsz & kbuf->buf_align.
 *
 * Returns 0 on success, negative errno on error.
 */
int arch_kexec_locate_mem_hole(struct kexec_buf *kbuf)
{
	struct crash_mem **emem;
	u64 buf_min, buf_max;
	int ret;

	/*
	 * Use the generic kexec_locate_mem_hole for regular
	 * kexec_file_load syscall
	 */
	if (kbuf->image->type != KEXEC_TYPE_CRASH)
		return kexec_locate_mem_hole(kbuf);

	/* Look up the exclude ranges list while locating the memory hole */
	emem = &(kbuf->image->arch.exclude_ranges);
	if (!(*emem) || ((*emem)->nr_ranges == 0)) {
		pr_warn("No exclude range list. Using the default locate mem hole method\n");
		return kexec_locate_mem_hole(kbuf);
	}

	/* Segments for kdump kernel should be within crashkernel region */
	buf_min = (kbuf->buf_min < crashk_res.start ?
		   crashk_res.start : kbuf->buf_min);
	buf_max = (kbuf->buf_max > crashk_res.end ?
		   crashk_res.end : kbuf->buf_max);

	if (buf_min > buf_max) {
		pr_err("Invalid buffer min and/or max values\n");
		return -EINVAL;
	}

	if (kbuf->top_down)
		ret = locate_mem_hole_top_down_ppc64(kbuf, buf_min, buf_max,
						     *emem);
	else
		ret = locate_mem_hole_bottom_up_ppc64(kbuf, buf_min, buf_max,
						      *emem);

	/* Add the buffer allocated to the exclude list for the next lookup */
	if (!ret) {
		add_mem_range(emem, kbuf->mem, kbuf->memsz);
		sort_memory_ranges(*emem, true);
	} else {
		pr_err("Failed to locate memory buffer of size %lu\n",
		       kbuf->memsz);
	}
	return ret;
}

/**
 * arch_kexec_apply_relocations_add - Apply relocations of type RELA
 * @pi:                               Purgatory Info.
 * @section:                          Section relocations applying to.
 * @relsec:                           Section containing RELAs.
 * @symtab:                           Corresponding symtab.
 *
 * Returns 0 on success, negative errno on error.
 */
int arch_kexec_apply_relocations_add(struct purgatory_info *pi,
				     Elf_Shdr *section,
				     const Elf_Shdr *relsec,
				     const Elf_Shdr *symtab)
{
	const char *strtab, *name, *shstrtab;
	int i, r_type, ret, err = -ENOEXEC;
	const Elf_Shdr *sechdrs;
	unsigned long my_r2;
	Elf_Rela *relas;

	/* String & section header string table */
	sechdrs = (void *)pi->ehdr + pi->ehdr->e_shoff;
	strtab = (char *)pi->ehdr + sechdrs[symtab->sh_link].sh_offset;
	shstrtab = (char *)pi->ehdr + sechdrs[pi->ehdr->e_shstrndx].sh_offset;

	relas = (void *)pi->ehdr + relsec->sh_offset;

	pr_debug("Applying relocate section %s to %u\n",
		 shstrtab + relsec->sh_name, relsec->sh_info);

	/* Get the TOC pointer (r2) */
	my_r2 = get_toc_ptr(pi);
	if (!my_r2)
		return err;

	for (i = 0; i < relsec->sh_size / sizeof(*relas); i++) {
		const Elf_Sym *sym;	/* symbol to relocate */
		unsigned long addr;	/* final location after relocation */
		unsigned long val;	/* relocated symbol value */
		void *loc;		/* tmp location to modify */

		sym = (void *)pi->ehdr + symtab->sh_offset;
		sym += ELF64_R_SYM(relas[i].r_info);

		if (sym->st_name)
			name = strtab + sym->st_name;
		else
			name = shstrtab + sechdrs[sym->st_shndx].sh_name;

		pr_debug("Symbol: %s info: %x shndx: %x value=%llx size: %llx\n",
			 name, sym->st_info, sym->st_shndx, sym->st_value,
			 sym->st_size);

		if ((sym->st_shndx == SHN_UNDEF) &&
		    (ELF_ST_TYPE(sym->st_info) != STT_NOTYPE)) {
			pr_err("Undefined symbol: %s\n", name);
			return err;
		}

		if (sym->st_shndx == SHN_COMMON) {
			pr_err("symbol '%s' in common section\n", name);
			return err;
		}

		if ((sym->st_shndx >= pi->ehdr->e_shnum) &&
		    (sym->st_shndx != SHN_ABS)) {
			pr_err("Invalid section %d for symbol %s\n",
			       sym->st_shndx, name);
			return err;
		}

		loc = pi->purgatory_buf;
		loc += section->sh_offset;
		loc += relas[i].r_offset;

		val = sym->st_value;
		if (sym->st_shndx != SHN_ABS)
			val += pi->sechdrs[sym->st_shndx].sh_addr;
		val += relas[i].r_addend;

		addr = section->sh_addr + relas[i].r_offset;

		pr_debug("Symbol: %s value=%lx address=%lx\n", name, val, addr);

		r_type = ELF64_R_TYPE(relas[i].r_info);
		ret = __kexec_do_relocs(my_r2, sym, r_type, loc, val, addr);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * arch_kexec_kernel_image_probe - Does additional handling needed to setup
 *                                 kexec segments.
 * @image:                         kexec image being loaded.
 * @buf:                           Buffer pointing to elf data.
 * @buf_len:                       Length of the buffer.
 *
 * Returns 0 on success, negative errno on error.
 */
int arch_kexec_kernel_image_probe(struct kimage *image, void *buf,
				  unsigned long buf_len)
{
	if (image->type == KEXEC_TYPE_CRASH) {
		int ret;

		/* Get exclude memory ranges needed for setting up kdump segments */
		ret = get_exclude_memory_ranges(&(image->arch.exclude_ranges));
		if (ret)
			pr_err("Failed to setup exclude memory ranges for buffer lookup\n");
		/* Return this until all changes for panic kernel are in */
		return -EOPNOTSUPP;
	}

	return kexec_image_probe_default(image, buf, buf_len);
}

/**
 * arch_kimage_file_post_load_cleanup - Frees up all the allocations done
 *                                      while loading the image.
 * @image:                              kexec image being loaded.
 *
 * Returns 0 on success, negative errno on error.
 */
int arch_kimage_file_post_load_cleanup(struct kimage *image)
{
	kfree(image->arch.exclude_ranges);
	image->arch.exclude_ranges = NULL;

	vfree(image->arch.backup_buf);
	image->arch.backup_buf = NULL;

	return kexec_image_post_load_cleanup_default(image);
}
