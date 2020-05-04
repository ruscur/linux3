// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Microsoft Corporation.
 */

#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/of.h>
#include <linux/memblock.h>
#include <linux/libfdt.h>
#include <linux/of_address.h>

static bool dtb_status_enabled;
static struct resource mem_res;
static void *vaddr;


/**
 * of_is_ima_memory_reserved - check if memory is reserved via device
 *							tree.
 *	Return: zero when memory is not reserved.
 *			positive number on success.
 *
 */
int of_is_ima_memory_reserved(void)
{
	return dtb_status_enabled;
}

/**
 * of_ima_write_buffer - Write the ima buffer into the reserved memory.
 *
 * ima_buffer - buffer starting address.
 * ima_buffer_size - size of segment.
 *
 * Return: 0 on success, negative errno on error.
 */
int of_ima_write_buffer(void *ima_buffer, size_t ima_buffer_size)
{
	void *addr;

	if (!dtb_status_enabled)
		return -EOPNOTSUPP;

	vaddr = memremap(mem_res.start, resource_size(&mem_res), MEMREMAP_WB);
	pr_info("Mapped reserved memory, vaddr: 0x%0llX, paddr: 0x%0llX\n , size : %lld",
	(u64)vaddr, mem_res.start, resource_size(&mem_res));

	if (vaddr) {
		memcpy(vaddr, &ima_buffer_size, sizeof(size_t));
		addr =  vaddr + sizeof(size_t);
		memcpy(addr, ima_buffer, ima_buffer_size);
		memunmap(vaddr);
		vaddr = NULL;
	}

	return 0;
}

/**
 * of_remove_ima_buffer - Write 0(Zero length buffer to read)to the
 *                        size location of the buffer.
 *
 * Return: 0 on success, negative errno on error.
 */
int of_remove_ima_buffer(void)
{
	size_t empty_buffer_size = 0;

	if (!dtb_status_enabled)
		return -ENOTSUPP;

	if (vaddr) {
		memcpy(vaddr, &empty_buffer_size, sizeof(size_t));
		memunmap(vaddr);
		vaddr = NULL;
	}

	return 0;
}

/**
 * of_ima_get_size_allocated - Get the usable buffer size thats allocated in
 *                             the device-tree.
 *
 * Return: 0 on unavailable node, size of the memory block - (size_t)
 */
size_t of_ima_get_size_allocated(void)
{
	size_t size = 0;

	if (!dtb_status_enabled)
		return size;

	size = resource_size(&mem_res) - sizeof(size_t);
	return size;
}

/**
 * of_get_ima_buffer - Get IMA buffer address.
 *
 * @addr:       On successful return, set to point to the buffer contents.
 * @size:       On successful return, set to the buffer size.
 *
 * Return: 0 on success, negative errno on error.
 */
int of_get_ima_buffer(void **addr, size_t *size)
{
	if (!dtb_status_enabled)
		return -ENOTSUPP;

	vaddr = memremap(mem_res.start, resource_size(&mem_res), MEMREMAP_WB);
	pr_info("Mapped reserved memory, vaddr: 0x%0llX, paddr: 0x%0llX,\n allocated size : %lld, ima_buffer_size: %ld ",
	(u64)vaddr, mem_res.start, resource_size(&mem_res), *(size_t *)vaddr);

	*size = *(size_t *)vaddr;
	*addr = vaddr + sizeof(size_t);
	return 0;
}

static const struct of_device_id ima_buffer_pass_ids[] = {
	{
		.compatible = "linux,ima_buffer_pass",
	},
	{}
};

static const struct of_device_id ima_buffer_pass_match[] = {
	{
		.name = "ima_buffer_pass",
	},
};
MODULE_DEVICE_TABLE(of, ima_buffer_pass_match);

static int __init ima_buffer_pass_init(void)
{
	int ret = 0;
	struct device_node *memnp;
	struct device_node *ima_buffer_pass_node;

	ima_buffer_pass_node = of_find_matching_node(NULL, ima_buffer_pass_ids);
	if (!ima_buffer_pass_node)
		return -ENOENT;

	memnp = of_parse_phandle(ima_buffer_pass_node, "memory-region", 0);
	if (!memnp)
		return -ENXIO;

	ret = of_address_to_resource(memnp, 0, &mem_res);
	if (ret < 0)
		return -ENOENT;

	of_node_put(memnp);
	dtb_status_enabled = true;

	return ret;
}

static void __exit ima_buffer_pass_exit(void)
{
	pr_info("trying to exit the ima driver\n");
}

module_init(ima_buffer_pass_init);
module_exit(ima_buffer_pass_exit);
