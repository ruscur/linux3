/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_POWERPC_CRASHDUMP_PPC64_H
#define _ASM_POWERPC_CRASHDUMP_PPC64_H

/* min & max addresses for kdump load segments */
#define KDUMP_BUF_MIN		(crashk_res.start)
#define KDUMP_BUF_MAX		((crashk_res.end < ppc64_rma_size) ? \
				 crashk_res.end : (ppc64_rma_size - 1))

#endif /* __ASM_POWERPC_CRASHDUMP_PPC64_H */
