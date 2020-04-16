// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Vivo Communication Technology Co. Ltd.
 * Copyright (C) 2020 Wang Wenhu <wenhu.wang@vivo.com>
 * All rights reserved.
 */

#include <linux/platform_device.h>
#include <linux/uio_driver.h>
#include <linux/stringify.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/fsl_85xx_cache_sram.h>

#define DRIVER_NAME	"uio_fsl_85xx_cache_sram"
#define UIO_INFO_VER	"devicetree,pseudo"
#define UIO_NAME	"uio_cache_sram"

static void uio_info_free_internal(struct uio_info *info)
{
	int i;

	for (i = 0; i < MAX_UIO_MAPS; i++) {
		struct uio_mem *uiomem = &info->mem[i];

		if (uiomem->internal_addr) {
			mpc85xx_cache_sram_free(uiomem->internal_addr);
			memset(uiomem, 0, sizeof(*uiomem));
		}
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
	int ret;

	/* alloc uio_info for one device */
	info = devm_kzalloc(&pdev->dev, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	/* get optional uio name */
	if (of_property_read_string(parent, "uio_name", &dt_name))
		dt_name = UIO_NAME;

	info->name = devm_kstrdup(&pdev->dev, dt_name, GFP_KERNEL);
	if (!info->name)
		return -ENOMEM;

	uiomem = info->mem;
	for_each_child_of_node(parent, node) {
		void *virt;
		phys_addr_t phys;

		ret = of_property_read_u32(node, "cache-mem-size", &mem_size);
		if (ret) {
			ret = -EINVAL;
			goto err_out;
		}

		if (mem_size == 0) {
			dev_err(&pdev->dev, "error cache-mem-size should not be 0\n");
			ret = -EINVAL;
			goto err_out;
		}

		virt = mpc85xx_cache_sram_alloc(mem_size, &phys,
						roundup_pow_of_two(mem_size));
		if (!virt) {
			/* mpc85xx_cache_sram_alloc to define the real cause */
			ret = -ENOMEM;
			goto err_out;
		}

		uiomem->memtype = UIO_MEM_PHYS;
		uiomem->addr = phys;
		uiomem->size = mem_size;
		uiomem->name = kstrdup(node->name, GFP_KERNEL);;
		uiomem->internal_addr = virt;
		uiomem++;

		if (uiomem >= &info->mem[MAX_UIO_MAPS]) {
			dev_warn(&pdev->dev, "more than %d uio-maps for device.\n",
				 MAX_UIO_MAPS);
			break;
		}
	}

	if (uiomem == info->mem) {
		dev_err(&pdev->dev, "error no valid uio-map configuration found\n");
		return -EINVAL;
	}

	info->version = UIO_INFO_VER;

	/* register uio device */
	if (uio_register_device(&pdev->dev, info)) {
		dev_err(&pdev->dev, "error uio,cache-sram registration failed\n");
		ret = -ENODEV;
		goto err_out;
	}

	platform_set_drvdata(pdev, info);

	return 0;
err_out:
	uio_info_free_internal(info);
	return ret;
}

static int uio_fsl_85xx_cache_sram_remove(struct platform_device *pdev)
{
	struct uio_info *info = platform_get_drvdata(pdev);

	uio_unregister_device(info);

	uio_info_free_internal(info);

	return 0;
}

static const struct of_device_id uio_mpc85xx_l2ctlr_of_match[] = {
	{	.compatible = "uio,mpc85xx-cache-sram",	},
	{},
};

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
