// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) IBM Corporation, 2014, 2017
 * Anton Blanchard, Rashmica Gupta.
 */

#define pr_fmt(fmt) "memtrace: " fmt

#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/memblock.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/numa.h>
#include <asm/machdep.h>
#include <asm/debugfs.h>

/* This enables us to keep track of the memory removed from each node. */
struct memtrace_entry {
	void *mem;
	u64 start;
	u64 size;
	u32 nid;
	struct dentry *dir;
	char name[16];
};

static u64 memtrace_size;

static struct memtrace_entry *memtrace_array;
static unsigned int memtrace_array_nr;


static ssize_t memtrace_read(struct file *filp, char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	struct memtrace_entry *ent = filp->private_data;

	return simple_read_from_buffer(ubuf, count, ppos, ent->mem, ent->size);
}

static const struct file_operations memtrace_fops = {
	.llseek = default_llseek,
	.read	= memtrace_read,
	.open	= simple_open,
};

static int online_mem_block(struct memory_block *mem, void *arg)
{
	return device_online(&mem->dev);
}

static int memtrace_free_node(int nid, unsigned long start, unsigned long size)
{
	int ret;

	ret = add_memory(nid, start, size);
	if (!ret) {
		/*
		 * If the kernel isn't compiled with the auto online option, we
		 * will try to online ourselves. We'll ignore any errors here -
		 * user space can try to online itself later (after all, the
		 * memory was added successfully).
		 */
		if (!memhp_auto_online) {
			lock_device_hotplug();
			walk_memory_blocks(start, size, NULL, online_mem_block);
			unlock_device_hotplug();
		}
	}
	return ret;
}

struct memtrace_alloc_info {
	struct notifier_block memory_notifier;
	unsigned long base_pfn;
	unsigned long nr_pages;
};

static int memtrace_memory_notifier_cb(struct notifier_block *nb,
				       unsigned long action, void *arg)
{
	struct memtrace_alloc_info *info = container_of(nb,
						     struct memtrace_alloc_info,
						     memory_notifier);
	unsigned long pfn, start_pfn, end_pfn;
	const struct memory_notify *mhp = arg;
	static bool going_offline;

	/* Ignore ranges that don't overlap. */
	if (mhp->start_pfn + mhp->nr_pages <= info->base_pfn ||
	    info->base_pfn + info->nr_pages <= mhp->start_pfn)
		return NOTIFY_OK;

	start_pfn = max_t(unsigned long, info->base_pfn, mhp->start_pfn);
	end_pfn = min_t(unsigned long, info->base_pfn + info->nr_pages,
			mhp->start_pfn + mhp->nr_pages);

	/*
	 * Drop our reference to the allocated (PageOffline()) pages, but
	 * reaquire them in case offlining fails. We might get called for
	 * MEM_CANCEL_OFFLINE but not for MEM_GOING_OFFLINE in case another
	 * notifier aborted offlining.
	 */
	switch (action) {
	case MEM_GOING_OFFLINE:
		for (pfn = start_pfn; pfn < end_pfn; pfn++)
			page_ref_dec(pfn_to_page(pfn));
		going_offline = true;
		break;
	case MEM_CANCEL_OFFLINE:
		if (going_offline)
			for (pfn = start_pfn; pfn < end_pfn; pfn++)
				page_ref_inc(pfn_to_page(pfn));
		going_offline = false;
		break;
	case MEM_GOING_ONLINE:
		/*
		 * While our notifier is active, user space could
		 * offline+re-online this memory. Disallow any such activity.
		 */
		return notifier_to_errno(-EBUSY);
	}
	return NOTIFY_OK;
}

static u64 memtrace_alloc_node(u32 nid, u64 size)
{
	const unsigned long memory_block_bytes = memory_block_size_bytes();
	const unsigned long nr_pages = size >> PAGE_SHIFT;
	struct memtrace_alloc_info info = {
		.memory_notifier = {
			.notifier_call = memtrace_memory_notifier_cb,
		},
	};
	unsigned long base_pfn, to_remove_pfn, pfn;
	struct page *page;
	int ret;

	if (!node_spanned_pages(nid))
		return 0;

	/*
	 * Try to allocate memory (that might span multiple memory blocks)
	 * on the requested node. Trace memory needs to be aligned to the size,
	 * which is guaranteed by alloc_contig_pages().
	 */
	page = alloc_contig_pages(nr_pages, __GFP_THISNODE, nid, NULL);
	if (!page)
		return 0;
	to_remove_pfn = base_pfn = page_to_pfn(page);
	info.base_pfn = base_pfn;
	info.nr_pages = nr_pages;

	/* PageOffline() allows to isolate the memory when offlining. */
	for (pfn = base_pfn; pfn < base_pfn + nr_pages; pfn++)
		__SetPageOffline(pfn_to_page(pfn));

	/* A temporary memory notifier allows to offline the isolated memory. */
	ret = register_memory_notifier(&info.memory_notifier);
	if (ret)
		goto out_free_pages;

	/*
	 * Try to offline and remove all involved memory blocks. This will
	 * only fail in the unlikely event that another memory notifier NACKs
	 * the offlining request - no memory has to be migrated.
	 *
	 * Remove memory in memory block size chunks so that iomem resources
	 * are always split to the same size and we never try to remove memory
	 * that spans two iomem resources.
	 */
	for (; to_remove_pfn < base_pfn + nr_pages;
	     to_remove_pfn += PHYS_PFN(memory_block_bytes)) {
		ret = offline_and_remove_memory(nid, PFN_PHYS(to_remove_pfn),
						memory_block_bytes);
		if (ret)
			goto out_readd_memory;
	}

	unregister_memory_notifier(&info.memory_notifier);
	return PFN_PHYS(base_pfn);
out_readd_memory:
	/* Unregister before adding+onlining (notifer blocks onlining). */
	unregister_memory_notifier(&info.memory_notifier);
	if (to_remove_pfn != base_pfn) {
		ret = memtrace_free_node(nid, PFN_PHYS(base_pfn),
					 PFN_PHYS(to_remove_pfn - base_pfn));
		if (ret)
			/* Even more unlikely, log and ignore. */
			pr_err("Failed to add trace memory to node %d\n", nid);
	}
out_free_pages:
	/* Only free memory that was not temporarily offlined+removed. */
	for (pfn = to_remove_pfn; pfn < base_pfn + nr_pages; pfn++)
		__ClearPageOffline(pfn_to_page(pfn));
	free_contig_range(to_remove_pfn, nr_pages - (to_remove_pfn - base_pfn));
	return 0;
}

static int memtrace_init_regions_runtime(u64 size)
{
	u32 nid;
	u64 m;

	memtrace_array = kcalloc(num_online_nodes(),
				sizeof(struct memtrace_entry), GFP_KERNEL);
	if (!memtrace_array) {
		pr_err("Failed to allocate memtrace_array\n");
		return -EINVAL;
	}

	for_each_online_node(nid) {
		m = memtrace_alloc_node(nid, size);

		/*
		 * A node might not have any local memory, so warn but
		 * continue on.
		 */
		if (!m) {
			pr_err("Failed to allocate trace memory on node %d\n", nid);
			continue;
		}

		pr_info("Allocated trace memory on node %d at 0x%016llx\n", nid, m);

		memtrace_array[memtrace_array_nr].start = m;
		memtrace_array[memtrace_array_nr].size = size;
		memtrace_array[memtrace_array_nr].nid = nid;
		memtrace_array_nr++;
	}

	return 0;
}

static struct dentry *memtrace_debugfs_dir;

static int memtrace_init_debugfs(void)
{
	int ret = 0;
	int i;

	for (i = 0; i < memtrace_array_nr; i++) {
		struct dentry *dir;
		struct memtrace_entry *ent = &memtrace_array[i];

		ent->mem = ioremap(ent->start, ent->size);
		/* Warn but continue on */
		if (!ent->mem) {
			pr_err("Failed to map trace memory at 0x%llx\n",
				 ent->start);
			ret = -1;
			continue;
		}

		snprintf(ent->name, 16, "%08x", ent->nid);
		dir = debugfs_create_dir(ent->name, memtrace_debugfs_dir);
		if (!dir) {
			pr_err("Failed to create debugfs directory for node %d\n",
				ent->nid);
			return -1;
		}

		ent->dir = dir;
		debugfs_create_file("trace", 0400, dir, ent, &memtrace_fops);
		debugfs_create_x64("start", 0400, dir, &ent->start);
		debugfs_create_x64("size", 0400, dir, &ent->size);
	}

	return ret;
}

/*
 * Iterate through the chunks of memory we have removed from the kernel
 * and attempt to add them back to the kernel.
 */
static int memtrace_online(void)
{
	int i, ret = 0;
	struct memtrace_entry *ent;

	for (i = memtrace_array_nr - 1; i >= 0; i--) {
		ent = &memtrace_array[i];

		/* We have onlined this chunk previously */
		if (ent->nid == NUMA_NO_NODE)
			continue;

		/* Remove from io mappings */
		if (ent->mem) {
			iounmap(ent->mem);
			ent->mem = 0;
		}

		if (memtrace_free_node(ent->nid, ent->start, ent->size)) {
			pr_err("Failed to add trace memory to node %d\n",
				ent->nid);
			ret += 1;
			continue;
		}

		/*
		 * Memory was added successfully so clean up references to it
		 * so on reentry we can tell that this chunk was added.
		 */
		debugfs_remove_recursive(ent->dir);
		pr_info("Added trace memory back to node %d\n", ent->nid);
		ent->size = ent->start = ent->nid = NUMA_NO_NODE;
	}
	if (ret)
		return ret;

	/* If all chunks of memory were added successfully, reset globals */
	kfree(memtrace_array);
	memtrace_array = NULL;
	memtrace_size = 0;
	memtrace_array_nr = 0;
	return 0;
}

static int memtrace_enable_set(void *data, u64 val)
{
	const unsigned long bytes = memory_block_size_bytes();

	if (val && (!is_power_of_2(val) || val < bytes)) {
		pr_err("Value must be 0 or a power of 2 (at least 0x%lx)\n",
		       bytes);
		return -EINVAL;
	}

	/* Re-add/online previously removed/offlined memory */
	if (memtrace_size) {
		if (memtrace_online())
			return -EAGAIN;
	}

	if (!val)
		return 0;

	/* Offline and remove memory */
	if (memtrace_init_regions_runtime(val))
		return -EINVAL;

	if (memtrace_init_debugfs())
		return -EINVAL;

	memtrace_size = val;

	return 0;
}

static int memtrace_enable_get(void *data, u64 *val)
{
	*val = memtrace_size;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(memtrace_init_fops, memtrace_enable_get,
					memtrace_enable_set, "0x%016llx\n");

static int memtrace_init(void)
{
	memtrace_debugfs_dir = debugfs_create_dir("memtrace",
						  powerpc_debugfs_root);
	if (!memtrace_debugfs_dir)
		return -1;

	debugfs_create_file("enable", 0600, memtrace_debugfs_dir,
			    NULL, &memtrace_init_fops);

	return 0;
}
machine_device_initcall(powernv, memtrace_init);
