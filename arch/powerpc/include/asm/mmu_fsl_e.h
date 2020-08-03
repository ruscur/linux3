/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_POWERPC_MMU_FSL_E_H_
#define _ASM_POWERPC_MMU_FSL_E_H_

#ifdef CONFIG_PPC_FSL_BOOK3E
#include <asm/percpu.h>
DECLARE_PER_CPU(int, next_tlbcam_idx);
#endif

#endif
