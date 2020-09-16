// SPDX-License-Identifier: GPL-2.0
/*
 * Machine Check Exception injection code
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <asm/debugfs.h>

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
	struct paca_struct *paca;

	flags = SLB_VSID_KERNEL | mmu_psize_defs[MMU_PAGE_64K].sllp;

	preempt_disable();

	paca = get_paca();

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

static ssize_t inject_slb_multihit(const char __user *u_buf, size_t count)
{
	char buf[32];
	size_t buf_size;

	buf_size = min(count, (sizeof(buf) - 1));
	if (copy_from_user(buf, u_buf, buf_size))
		return -EFAULT;
	buf[buf_size] = '\0';

	if (buf[0] != '1')
		return -EINVAL;

	inject_vmalloc_slb_multihit();
	inject_kmalloc_slb_multihit();
	return count;
}

static ssize_t inject_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	static ssize_t (*func)(const char __user *, size_t);

	func = file->f_inode->i_private;
	return func(buf, count);
}

static const struct file_operations inject_fops = {
	.write		= inject_write,
	.llseek		= default_llseek,
};

static int mce_error_inject_setup(void)
{
	struct dentry *mce_error_inject_dir;

	mce_error_inject_dir = debugfs_create_dir("mce_error_inject",
						  powerpc_debugfs_root);

	if (mmu_has_feature(MMU_FTR_HPTE_TABLE)) {
		(void)debugfs_create_file("inject_slb_multihit", 0200,
					  mce_error_inject_dir,
					  &inject_slb_multihit,
					  &inject_fops);
	}

	return 0;
}

device_initcall(mce_error_inject_setup);
