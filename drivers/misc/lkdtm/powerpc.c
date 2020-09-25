// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>
#include <linux/vmalloc.h>

static inline unsigned long get_slb_index(void)
{
	unsigned long index;

	index = get_paca()->stab_rr;

	/*
	 * simple round-robin replacement of slb starting at SLB_NUM_BOLTED.
	 */
	if (index < (mmu_slb_size - 1))
		index++;
	else
		index = SLB_NUM_BOLTED;
	get_paca()->stab_rr = index;
	return index;
}

#define slb_esid_mask(ssize)	\
	(((ssize) == MMU_SEGSIZE_256M) ? ESID_MASK : ESID_MASK_1T)

static inline unsigned long mk_esid_data(unsigned long ea, int ssize,
					 unsigned long slot)
{
	return (ea & slb_esid_mask(ssize)) | SLB_ESID_V | slot;
}

#define slb_vsid_shift(ssize)	\
	((ssize) == MMU_SEGSIZE_256M ? SLB_VSID_SHIFT : SLB_VSID_SHIFT_1T)

static inline unsigned long mk_vsid_data(unsigned long ea, int ssize,
					 unsigned long flags)
{
	return (get_kernel_vsid(ea, ssize) << slb_vsid_shift(ssize)) | flags |
		((unsigned long)ssize << SLB_VSID_SSIZE_SHIFT);
}

static void insert_slb_entry(char *p, int ssize)
{
	unsigned long flags, entry;

	flags = SLB_VSID_KERNEL | mmu_psize_defs[MMU_PAGE_64K].sllp;
	preempt_disable();

	entry = get_slb_index();
	asm volatile("slbmte %0,%1" :
			: "r" (mk_vsid_data((unsigned long)p, ssize, flags)),
			  "r" (mk_esid_data((unsigned long)p, ssize, entry))
			: "memory");

	entry = get_slb_index();
	asm volatile("slbmte %0,%1" :
			: "r" (mk_vsid_data((unsigned long)p, ssize, flags)),
			  "r" (mk_esid_data((unsigned long)p, ssize, entry))
			: "memory");
	preempt_enable();
	p[0] = '!';
}

static void inject_vmalloc_slb_multihit(void)
{
	char *p;

	p = vmalloc(2048);
	if (!p)
		return;

	insert_slb_entry(p, MMU_SEGSIZE_1T);
	vfree(p);
}

static void inject_kmalloc_slb_multihit(void)
{
	char *p;

	p = kmalloc(2048, GFP_KERNEL);
	if (!p)
		return;

	insert_slb_entry(p, MMU_SEGSIZE_1T);
	kfree(p);
}

static void insert_dup_slb_entry_0(void)
{
	unsigned long test_address = 0xC000000000000000;
	volatile unsigned long *test_ptr;
	unsigned long entry, i = 0;
	unsigned long esid, vsid;

	test_ptr = (unsigned long *)test_address;
	preempt_disable();

	asm volatile("slbmfee  %0,%1" : "=r" (esid) : "r" (i));
	asm volatile("slbmfev  %0,%1" : "=r" (vsid) : "r" (i));
	entry = get_slb_index();

	/* for i !=0 we would need to mask out the old entry number */
	asm volatile("slbmte %0,%1" :
			: "r" (vsid),
			  "r" (esid | entry)
			: "memory");

	asm volatile("slbmfee  %0,%1" : "=r" (esid) : "r" (i));
	asm volatile("slbmfev  %0,%1" : "=r" (vsid) : "r" (i));
	entry = get_slb_index();

	/* for i !=0 we would need to mask out the old entry number */
	asm volatile("slbmte %0,%1" :
			: "r" (vsid),
			  "r" (esid | entry)
			: "memory");

	pr_info("lkdtm: %s accessing test address 0x%lx: 0x%lx\n",
		__func__, test_address, *test_ptr);

	preempt_enable();
}

void lkdtm_PPC_SLB_MULTIHIT(void)
{
	if (mmu_has_feature(MMU_FTR_HPTE_TABLE)) {
		inject_vmalloc_slb_multihit();
		inject_kmalloc_slb_multihit();
		insert_dup_slb_entry_0();
	}
	pr_info("Recovered from SLB multihit. (Ignore this message on non HPTE machines)");
}
