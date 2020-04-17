// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Vivo Communication Technology Co. Ltd.
 * Copyright (C) 2020 Wang Wenhu <wenhu.wang@vivo.com>
 * All rights reserved.
 */

#include <linux/platform_device.h>
#include <linux/uio_driver.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/of_address.h>

#define DRIVER_NAME	"uio_fsl_85xx_cache_sram"
#define UIO_INFO_VER	"devicetree,pseudo"

#define MAX_SRAM_UIO_INFOS	5

#define L2CR_L2FI		0x40000000	/* L2 flash invalidate */
#define L2CR_SRAM_FULL		0x00010000	/* L2SRAM full size */
#define L2CR_SRAM_HALF		0x00020000	/* L2SRAM half size */
#define L2CR_SRAM_QUART		0x00040000	/* L2SRAM one quarter size */
#define L2CR_SRAM_EIGHTH	0x00060000	/* L2SRAM one eighth size */

#define L2SRAM_BAR_MSK_LO18	0xFFFFC000	/* Lower 18 bits */
#define L2SRAM_BARE_MSK_HI4	0x0000000F	/* Upper 4 bits */

enum cache_sram_lock_ways {
	LOCK_WAYS_ZERO,
	LOCK_WAYS_EIGHTH,
	LOCK_WAYS_TWO_EIGHTH,
	LOCK_WAYS_HALF = 4,
	LOCK_WAYS_FULL = 8,
};

struct mpc85xx_l2ctlr {
	u32	ctl;		/* 0x000 - L2 control */
	u8	res1[0xC];
	u32	ewar0;		/* 0x010 - External write address 0 */
	u32	ewarea0;	/* 0x014 - External write address extended 0 */
	u32	ewcr0;		/* 0x018 - External write ctrl */
	u8	res2[4];
	u32	ewar1;		/* 0x020 - External write address 1 */
	u32	ewarea1;	/* 0x024 - External write address extended 1 */
	u32	ewcr1;		/* 0x028 - External write ctrl 1 */
	u8	res3[4];
	u32	ewar2;		/* 0x030 - External write address 2 */
	u32	ewarea2;	/* 0x034 - External write address extended 2 */
	u32	ewcr2;		/* 0x038 - External write ctrl 2 */
	u8	res4[4];
	u32	ewar3;		/* 0x040 - External write address 3 */
	u32	ewarea3;	/* 0x044 - External write address extended 3 */
	u32	ewcr3;		/* 0x048 - External write ctrl 3 */
	u8	res5[0xB4];
	u32	srbar0;		/* 0x100 - SRAM base address 0 */
	u32	srbarea0;	/* 0x104 - SRAM base addr reg ext address 0 */
	u32	srbar1;		/* 0x108 - SRAM base address 1 */
	u32	srbarea1;	/* 0x10C - SRAM base addr reg ext address 1 */
	u8	res6[0xCF0];
	u32	errinjhi;	/* 0xE00 - Error injection mask high */
	u32	errinjlo;	/* 0xE04 - Error injection mask low */
	u32	errinjctl;	/* 0xE08 - Error injection tag/ecc control */
	u8	res7[0x14];
	u32	captdatahi;	/* 0xE20 - Error data high capture */
	u32	captdatalo;	/* 0xE24 - Error data low capture */
	u32	captecc;	/* 0xE28 - Error syndrome */
	u8	res8[0x14];
	u32	errdet;		/* 0xE40 - Error detect */
	u32	errdis;		/* 0xE44 - Error disable */
	u32	errinten;	/* 0xE48 - Error interrupt enable */
	u32	errattr;	/* 0xE4c - Error attribute capture */
	u32	erradrrl;	/* 0xE50 - Error address capture low */
	u32	erradrrh;	/* 0xE54 - Error address capture high */
	u32	errctl;		/* 0xE58 - Error control */
	u8	res9[0x1A4];
};

/**
 * struct uio_cache_sram - controller for cache-sram and uio devices
 *
 * @base_phys:	physical address of cache-sram
 * @base_virt:	mapped virtual address of cache-sram
 * @size:	size of the sram could be used by user
 * @alloced:	size of the sram allocated while initiating uio_infos
 * @l2cache_size: total size of the cache-sram
 * @l2ctlr:	address of the l2-controller
 * @info_count:	count of the uio devices(info) for the cache-sram
 * @uio_infos:	address array of the uio devices(info)
 */
struct uio_cache_sram {
	phys_addr_t base_phys;
	void *base_virt;
	unsigned int size;
	unsigned int alloced;

	unsigned int l2cache_size;

	struct mpc85xx_l2ctlr __iomem *l2ctlr;

	unsigned int info_count;
	struct uio_info *uio_infos[MAX_SRAM_UIO_INFOS];
};

static int of_init_cache_sram(struct device_node *node,
			      struct uio_cache_sram *cache_sram)
{
	const __be32 *cell;

	if (of_property_read_u32(node, "cache-size",
				&cache_sram->l2cache_size)) {
		pr_err("%pOF: missing cache-size property\n", node);
		return -EINVAL;
	}

	cell = of_get_property(node, "sram-range", NULL);
	if (!cell) {
		pr_err("%pOF: missing sram-range property\n", node);
		return -EINVAL;
	}

	cache_sram->base_phys = of_read_number(cell, of_n_addr_cells(node));
	cache_sram->size = of_read_number(cell + of_n_addr_cells(node),
					  of_n_size_cells(node));

	return 0;
}

static void l2ctrl_init(struct uio_cache_sram *cache_sram)
{
	struct mpc85xx_l2ctlr *l2ctlr = cache_sram->l2ctlr;

	/* Write bits[0-17] to srbar0 */
	out_be32(&l2ctlr->srbar0,
		 lower_32_bits(cache_sram->base_phys) & L2SRAM_BAR_MSK_LO18);

	/* Write bits[18-21] to srbare0 */
#ifdef CONFIG_PHYS_64BIT
	out_be32(&l2ctlr->srbarea0,
		 upper_32_bits(cache_sram->base_phys) & L2SRAM_BARE_MSK_HI4);
#endif

	clrsetbits_be32(&l2ctlr->ctl, L2CR_L2E, L2CR_L2FI);

	switch (LOCK_WAYS_FULL * cache_sram->size / cache_sram->l2cache_size) {
	case LOCK_WAYS_EIGHTH:
		setbits32(&l2ctlr->ctl,
			  L2CR_L2E | L2CR_L2FI | L2CR_SRAM_EIGHTH);
		break;

	case LOCK_WAYS_TWO_EIGHTH:
		setbits32(&l2ctlr->ctl,
			  L2CR_L2E | L2CR_L2FI | L2CR_SRAM_QUART);
		break;

	case LOCK_WAYS_HALF:
		setbits32(&l2ctlr->ctl,
			  L2CR_L2E | L2CR_L2FI | L2CR_SRAM_HALF);
		break;

	case LOCK_WAYS_FULL:
	default:
		setbits32(&l2ctlr->ctl,
			  L2CR_L2E | L2CR_L2FI | L2CR_SRAM_FULL);
		break;
	}
	eieio();
}

static int uio_cache_sram_init(struct platform_device *pdev,
			       struct uio_cache_sram *cache_sram)
{
	struct device_node *node = pdev->dev.of_node;
	unsigned int rem;
	unsigned char ways;
	int ret;

	ret = of_init_cache_sram(node, cache_sram);
	if (ret)
		return ret;

	rem = cache_sram->l2cache_size % cache_sram->size;
	ways = LOCK_WAYS_FULL * cache_sram->size / cache_sram->l2cache_size;
	if (rem || (ways & (ways - 1))) {
		dev_err(&pdev->dev, "Illegal cache-size in command line\n");
		return -EINVAL;
	}

	cache_sram->l2ctlr = of_iomap(pdev->dev.of_node, 0);
	if (!cache_sram->l2ctlr) {
		dev_err(&pdev->dev, "error can't map l2-controller\n");
		return -EINVAL;
	}

	l2ctrl_init(cache_sram);

	if (!request_mem_region(cache_sram->base_phys, cache_sram->size,
				"fsl_85xx_cache_sram")) {
		dev_err(&pdev->dev, "%pOF: request memory failed\n",
				pdev->dev.of_node);
		ret = -ENXIO;
		goto out_unmap;
	}

	cache_sram->base_virt = ioremap_coherent(cache_sram->base_phys,
						 cache_sram->size);
	if (!cache_sram->base_virt) {
		dev_err(&pdev->dev, "%pOF: ioremap_coherent failed\n",
			pdev->dev.of_node);
		ret = -ENOMEM;
		goto out_release;
	}

	return 0;
out_release:
	release_mem_region(cache_sram->base_phys, cache_sram->size);
out_unmap:
	iounmap(cache_sram->l2ctlr);
	return ret;
}

static int uio_cache_sram_destroy(struct uio_cache_sram *cache_sram)
{
	iounmap(cache_sram->l2ctlr);
	iounmap(cache_sram->base_virt);
	release_mem_region(cache_sram->base_phys, cache_sram->size);

	return 0;
}

static void uio_info_free_internal(struct uio_info *info)
{
	int i;

	for (i = 0; i < MAX_UIO_MAPS; i++) {
		struct uio_mem *uiomem = &info->mem[i];

		if (uiomem->internal_addr)
			memset(uiomem, 0, sizeof(*uiomem));
	}
}

void uio_infos_unregister(struct uio_cache_sram *cache_sram)
{
	int i;

	for (i = 0; i < cache_sram->info_count; i++) {
		uio_unregister_device(cache_sram->uio_infos[i]);
		uio_info_free_internal(cache_sram->uio_infos[i]);
		cache_sram->uio_infos[i] = NULL;
	}

	cache_sram->info_count = 0;
}

static int uio_fsl_85xx_cache_sram_probe(struct platform_device *pdev)
{
	struct device_node *parent = pdev->dev.of_node;
	struct device_node *node = NULL;
	struct uio_cache_sram *cache_sram;
	struct uio_info *info;
	struct uio_mem *uiomem;
	const unsigned int *p;
	struct property *prop;
	const char *dt_name;
	u32 size;
	int ret;

	cache_sram = devm_kzalloc(&pdev->dev, sizeof(*cache_sram), GFP_KERNEL);
	if (!cache_sram)
		return -ENOMEM;

	ret = uio_cache_sram_init(pdev, cache_sram);
	if (ret)
		return ret;

	for_each_child_of_node(parent, node) {
		char buf[24];
		int map_idx = 0;

		/* alloc uio_info for one uio device */
		info = devm_kzalloc(&pdev->dev, sizeof(*info), GFP_KERNEL);
		if (!info)
			return -ENOMEM;

		/* get optional uio name */
		if (of_property_read_string(parent, "uio_name", &dt_name)) {
			sprintf(buf, "uio-sram%d", cache_sram->info_count);
			dt_name = buf;
		}

		info->name = devm_kstrdup(&pdev->dev, dt_name, GFP_KERNEL);
		if (!info->name)
			return -ENOMEM;

		of_property_for_each_u32(node, "uiomaps", prop, p, size) {
			char name[10];

			/* size should not be less than 2 */
			if (size < 2) {
				pr_err("size %x less than 2\n", size);
				return -EINVAL;
			}

			/* size should be 2^n aligned */
			if (size != roundup_pow_of_two(size)) {
				pr_err("size %x is not 2^n algiend\n", size);
				return -EINVAL;
			}

			if (cache_sram->alloced + size > cache_sram->size) {
				pr_err("size %x too big\n", size);
				return -EINVAL;
			}

			uiomem = &info->mem[map_idx];
			uiomem->addr = cache_sram->base_phys +
				       cache_sram->alloced;
			uiomem->internal_addr = cache_sram->base_virt +
						cache_sram->alloced;
			uiomem->size = size;
			uiomem->memtype = UIO_MEM_PHYS;

			cache_sram->alloced += size;

			sprintf(name, "mem%d", map_idx);
			uiomem->name = devm_kstrdup(&pdev->dev, name,
						    GFP_KERNEL);

			map_idx++;
			if (map_idx >= MAX_UIO_MAPS) {
				dev_warn(&pdev->dev, "more than %d uio-maps for device.\n",
					 MAX_UIO_MAPS);
				break;
			}
		}

		if (map_idx == 0) {
			dev_err(&pdev->dev, "error no valid uio-map configuration found\n");
			ret = -EINVAL;
			goto err_out;
		}

		info->version = UIO_INFO_VER;

		/* register uio device */
		if (uio_register_device(&pdev->dev, info)) {
			dev_err(&pdev->dev, "error uio,cache-sram registration failed\n");
			ret = -ENODEV;
			goto err_out;
		}

		cache_sram->uio_infos[cache_sram->info_count] = info;
		cache_sram->info_count++;

		if (cache_sram->info_count >= MAX_SRAM_UIO_INFOS) {
			dev_warn(&pdev->dev, "more than %d uio_info devices.\n",
				 MAX_SRAM_UIO_INFOS);
			break;
		}
	}

	platform_set_drvdata(pdev, cache_sram);

	return 0;
err_out:
	uio_infos_unregister(cache_sram);
	return ret;
}

static int uio_fsl_85xx_cache_sram_remove(struct platform_device *pdev)
{
	struct uio_cache_sram *cache_sram = platform_get_drvdata(pdev);

	uio_infos_unregister(cache_sram);

	uio_cache_sram_destroy(cache_sram);

	return 0;
}

#ifdef CONFIG_OF
static struct of_device_id uio_fsl_85xx_cache_sram_of_match[] = {
	{ /* This is filled with module_parm */ },
	{ /* Sentinel */ },
};
MODULE_DEVICE_TABLE(of, uio_fsl_85xx_cache_sram_of_match);

module_param_string(of_id, uio_fsl_85xx_cache_sram_of_match[0].compatible,
		    sizeof(uio_fsl_85xx_cache_sram_of_match[0].compatible), 0);
MODULE_PARM_DESC(of_id, "platform device id to be handled by cache-sram-uio");
#endif

static struct platform_driver uio_fsl_85xx_cache_sram = {
	.probe = uio_fsl_85xx_cache_sram_probe,
	.remove = uio_fsl_85xx_cache_sram_remove,
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table	= of_match_ptr(uio_fsl_85xx_cache_sram_of_match),
	},
};

module_platform_driver(uio_fsl_85xx_cache_sram);

MODULE_AUTHOR("Wang Wenhu <wenhu.wang@vivo.com>");
MODULE_DESCRIPTION("Freescale MPC85xx Cache-Sram UIO Platform Driver");
MODULE_ALIAS("platform:" DRIVER_NAME);
MODULE_LICENSE("GPL v2");
