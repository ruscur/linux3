// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file contains the routines for initializing the MMU
 * on the 4xx series of chips.
 */

#include <asm/processor.h>
#include <asm/page.h>
#include <asm/cache.h>

void flush_instruction_cache(void)
{
	iccci((void*)KERNELBASE);
	isync();
}
