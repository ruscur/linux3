/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __FSL_85XX_SRAM_H__
#define __FSL_85XX_SRAM_H__

extern struct mpc85xx_cache_sram *cache_sram;

static inline struct mpc85xx_cache_sram *mpc85xx_get_cache_sram(void)
{
	return cache_sram;
}

#endif /* __FSL_85XX_SRAM_H__ */
