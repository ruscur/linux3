/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_POWERPC_KEXEC_RANGES_H
#define _ASM_POWERPC_KEXEC_RANGES_H

#define MEM_RANGE_CHUNK_SZ		2048	/* Memory ranges size chunk */

struct crash_mem *realloc_mem_ranges(struct crash_mem **mem_ranges);
int add_mem_range(struct crash_mem **mem_ranges, u64 base, u64 size);
int add_tce_mem_ranges(struct crash_mem **mem_ranges);
int add_initrd_mem_range(struct crash_mem **mem_ranges);
int add_htab_mem_range(struct crash_mem **mem_ranges);
int add_kernel_mem_range(struct crash_mem **mem_ranges);
int add_rtas_mem_range(struct crash_mem **mem_ranges);
int add_opal_mem_range(struct crash_mem **mem_ranges);
int add_reserved_ranges(struct crash_mem **mem_ranges);
void sort_memory_ranges(struct crash_mem *mrngs, bool merge);

#endif /* _ASM_POWERPC_KEXEC_RANGES_H */
