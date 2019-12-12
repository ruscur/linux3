/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_KASAN_H
#define __ASM_KASAN_H

#include <asm/page.h>
#include <asm/pgtable.h>

#ifdef CONFIG_KASAN
#define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
#define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
#define EXPORT_SYMBOL_KASAN(fn)	EXPORT_SYMBOL(__##fn)
#else
#define _GLOBAL_KASAN(fn)	_GLOBAL(fn)
#define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(fn)
#define EXPORT_SYMBOL_KASAN(fn)
#endif

#ifndef __ASSEMBLY__

#ifdef CONFIG_KASAN
void kasan_init(void);
#else
static inline void kasan_init(void) { }
#endif

#define KASAN_SHADOW_SCALE_SHIFT	3

#define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))

#ifdef CONFIG_PPC32

#define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)

#define KASAN_SHADOW_END	0UL

#define KASAN_SHADOW_SIZE	(KASAN_SHADOW_END - KASAN_SHADOW_START)

#ifdef CONFIG_KASAN
void kasan_early_init(void);
void kasan_mmu_init(void);
#else
static inline void kasan_mmu_init(void) { }
#endif
#endif

#ifdef CONFIG_PPC_BOOK3S_64

#define KASAN_SHADOW_SIZE ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
				1024 * 1024 * 1 / 8)

#endif /* CONFIG_PPC_BOOK3S_64 */

#endif /* __ASSEMBLY */
#endif
