// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Vivo Communication Technology Co. Ltd.
 * Copyright (C) 2020 Wang Wenhu <wenhu.wang@vivo.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/platform_device.h>
#include <linux/uio_driver.h>
#include <linux/stringify.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/fsl_85xx_cache_sram.h>

#define DRIVER_VERSION	"0.1.0"
#define DRIVER_NAME	"uio_fsl_85xx_cache_sram"
#define UIO_NAME	"uio_cache_sram"

static const struct of_device_id uio_mpc85xx_l2ctlr_of_match[] = {
	{	.compatible = "uio,fsl,p2020-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p2010-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1020-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1011-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1013-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1022-l2-cache-controller",	},
	{	.compatible = "uio,fsl,mpc8548-l2-cache-controller",	},
	{	.compatible = "uio,fsl,mpc8544-l2-cache-controller",	},
	{	.compatible = "uio,fsl,mpc8572-l2-cache-controller",	},
	{	.compatible = "uio,fsl,mpc8536-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1021-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1012-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1025-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1016-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1024-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1015-l2-cache-controller",	},
	{	.compatible = "uio,fsl,p1010-l2-cache-controller",	},
	{	.compatible = "uio,fsl,bsc9131-l2-cache-controller",	},
	{},
};

static void uio_info_free_internal(struct uio_info *info)
{
	struct uio_mem *uiomem = &info->mem[0];

	while (uiomem < &info->mem[MAX_UIO_MAPS]) {
		if (uiomem->size) {
			mpc85xx_cache_sram_free(uiomem->internal_addr);
			kfree(uiomem->name);
		}
		uiomem++;
	}
}

static int uio_fsl_85xx_cache_sram_probe(struct platform_device *pdev)
{
	struct device_node *parent = pdev->dev.of_node;
	struct device_node *node = NULL;
	struct uio_info *info;
	struct uio_mem *uiomem;
	const char *dt_name;
	u32 mem_size;
	u32 align;
	void *virt;
	phys_addr_t phys;
	int ret = -ENODEV;

	/* alloc uio_info for one device */
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		dev_err(&pdev->dev, "kzalloc uio_info failed\n");
		ret = -ENOMEM;
		goto err_out;
	}

	/* get optional uio name */
	if (of_property_read_string(parent, "uio_name", &dt_name))
		dt_name = UIO_NAME;

	info->name = kstrdup(dt_name, GFP_KERNEL);
	if (!info->name) {
		dev_err(&pdev->dev, "error kstrdup uio_name\n");
		ret = -ENOMEM;
		goto err_info_free;
	}

	uiomem = &info->mem[0];
	for_each_child_of_node(parent, node) {
		if (!node) {
			dev_err(&pdev->dev, "device's OF-node is NULL\n");
			continue;
		}

		ret = of_property_read_u32(node, "cache-mem-size", &mem_size);
		if (ret) {
			dev_err(&pdev->dev, "missing cache-mem-size value\n");
			continue;
		}

		if (mem_size == 0) {
			dev_err(&pdev->dev, "cache-mem-size should not be 0\n");
			continue;
		}

		align = 2;
		while (align < mem_size)
			align *= 2;
		virt = mpc85xx_cache_sram_alloc(mem_size, &phys, align);
		if (!virt) {
			dev_err(&pdev->dev, "allocate 0x%x cache-mem failed\n", mem_size);
			continue;
		}

		uiomem->memtype = UIO_MEM_PHYS;
		uiomem->addr = phys;
		uiomem->size = mem_size;
		uiomem->name = kstrdup(node->name, GFP_KERNEL);;
		uiomem->internal_addr = virt;
		++uiomem;

		if (uiomem >= &info->mem[MAX_UIO_MAPS]) {
			dev_warn(&pdev->dev, "device has more than "
				 __stringify(MAX_UIO_MAPS)
				 " I/O memory resources.\n");
			break;
		}
	}

	while (uiomem < &info->mem[MAX_UIO_MAPS]) {
		uiomem->size = 0;
		++uiomem;
	}

	if (info->mem[0].size == 0) {
		dev_err(&pdev->dev, "error no valid uio-map configured\n");
		ret = -EINVAL;
		goto err_name_free;
	}

	info->version = DRIVER_VERSION;

	/* register UIO device */
	if (uio_register_device(&pdev->dev, info)) {
		dev_err(&pdev->dev, "UIO registration failed\n");
		ret = -ENODEV;
		goto err_unregister;
	}

	platform_set_drvdata(pdev, info);

	return 0;
err_unregister:
	uio_info_free_internal(info);
err_name_free:
	kfree(info->name);
err_info_free:
	kfree(info);
err_out:
	return ret;
}

static int uio_fsl_85xx_cache_sram_remove(struct platform_device *pdev)
{
	struct uio_info *info = platform_get_drvdata(pdev);

	uio_unregister_device(info);

	uio_info_free_internal(info);

	kfree(info->name);

	kfree(info);

	return 0;
}

static struct platform_driver uio_fsl_85xx_cache_sram = {
	.probe = uio_fsl_85xx_cache_sram_probe,
	.remove = uio_fsl_85xx_cache_sram_remove,
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table	= uio_mpc85xx_l2ctlr_of_match,
	},
};

module_platform_driver(uio_fsl_85xx_cache_sram);

MODULE_AUTHOR("Wang Wenhu <wenhu.wang@vivo.com>");
MODULE_DESCRIPTION("Freescale MPC85xx Cache-Sram UIO Platform Driver");
MODULE_ALIAS("platform:" DRIVER_NAME);
MODULE_LICENSE("GPL v2");
