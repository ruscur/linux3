// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 IBM Corporation
 *
 * Authors:
 * Thiago Jung Bauermann <bauerman@linux.vnet.ibm.com>
 */

#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/of.h>
#include <linux/memblock.h>
#include <linux/libfdt.h>

#ifdef CONFIG_IMA_KEXEC
/**
 * arch_ima_add_kexec_buffer - do arch-specific steps to add the IMA buffer
 *
 * Architectures should use this function to pass on the IMA buffer
 * information to the next kernel.
 *
 * Return: 0 on success, negative errno on error.
 */
int arch_ima_add_kexec_buffer(struct kimage *image, unsigned long load_addr,
			      size_t size)
{
	image->arch.ima_buffer_addr = load_addr;
	image->arch.ima_buffer_size = size;

	return 0;
}

static int write_number(void *p, u64 value, int cells)
{
	if (cells == 1) {
		u32 tmp;

		if (value > U32_MAX)
			return -EINVAL;

		tmp = cpu_to_be32(value);
		memcpy(p, &tmp, sizeof(tmp));
	} else if (cells == 2) {
		u64 tmp;

		tmp = cpu_to_be64(value);
		memcpy(p, &tmp, sizeof(tmp));
	} else
		return -EINVAL;

	return 0;
}

/**
 * setup_ima_buffer - add IMA buffer information to the fdt
 * @image:		kexec image being loaded.
 * @fdt:		Flattened device tree for the next kernel.
 * @chosen_node:	Offset to the chosen node.
 *
 * Return: 0 on success, or negative errno on error.
 */
int setup_ima_buffer(const struct kimage *image, void *fdt, int chosen_node)
{
	int ret, addr_cells, size_cells, entry_size;
	u8 value[16];

//	remove_ima_buffer(fdt, chosen_node);
	if (!image->arch.ima_buffer_size)
		return 0;

	ret = get_addr_size_cells(&addr_cells, &size_cells);
	if (ret)
		return ret;

	entry_size = 4 * (addr_cells + size_cells);

	if (entry_size > sizeof(value))
		return -EINVAL;

	ret = write_number(value, image->arch.ima_buffer_addr, addr_cells);
	if (ret)
		return ret;

	ret = write_number(value + 4 * addr_cells, image->arch.ima_buffer_size,
			   size_cells);
	if (ret)
		return ret;

	ret = fdt_setprop(fdt, chosen_node, "linux,ima-kexec-buffer", value,
			  entry_size);
	if (ret < 0)
		return -EINVAL;

	ret = fdt_add_mem_rsv(fdt, image->arch.ima_buffer_addr,
			      image->arch.ima_buffer_size);
	if (ret)
		return -EINVAL;

	pr_debug("IMA buffer at 0x%llx, size = 0x%zx\n",
		 image->arch.ima_buffer_addr, image->arch.ima_buffer_size);

	return 0;
}
#endif /* CONFIG_IMA_KEXEC */
