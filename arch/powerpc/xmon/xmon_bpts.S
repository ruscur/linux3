/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/ppc_asm.h>
#include <asm/asm-compat.h>
#include "xmon_bpts.h"

.global bpt_table
bpt_table:
	.space NBPTS * 8
