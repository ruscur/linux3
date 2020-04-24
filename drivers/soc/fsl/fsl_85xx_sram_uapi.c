// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Vivo Communication Technology Co. Ltd.
 * Copyright (C) 2020 Wang Wenhu <wenhu.wang@vivo.com>
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sram_dynamic.h>
#include <asm/fsl_85xx_cache_sram.h>
#include "fsl_85xx_sram.h"

static struct sram_api mpc85xx_sram_api = {
	.name = "mpc85xx_sram",
	.alloc = mpc85xx_cache_sram_alloc,
	.free = mpc85xx_cache_sram_free,
};

static int __init mpc85xx_sram_uapi_init(void)
{
	struct mpc85xx_cache_sram *sram = mpc85xx_get_cache_sram();

	if (!sram)
		return -ENODEV;

	return sram_register_device(sram->dev, &mpc85xx_sram_api);
}
subsys_initcall(mpc85xx_sram_uapi_init);

static void __exit mpc85xx_sram_uapi_exit(void)
{
	sram_unregister_device(&mpc85xx_sram_api);
}
module_exit(mpc85xx_sram_uapi_exit);

MODULE_AUTHOR("Wang Wenhu <wenhu.wang@vivo.com>");
MODULE_DESCRIPTION("MPC85xx SRAM User-Space API Support");
MODULE_LICENSE("GPL v2");
