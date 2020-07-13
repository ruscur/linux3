/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_POWERPC_CRASHDUMP_PPC64_H
#define _ASM_POWERPC_CRASHDUMP_PPC64_H

/* Backup region - first 64K bytes of System RAM. */
#define BACKUP_SRC_START	0
#define BACKUP_SRC_END		0xffff
#define BACKUP_SRC_SIZE		(BACKUP_SRC_END - BACKUP_SRC_START + 1)

/* min & max addresses for kdump load segments */
#define KDUMP_BUF_MIN		(crashk_res.start)
#define KDUMP_BUF_MAX		((crashk_res.end < ppc64_rma_size) ? \
				 crashk_res.end : (ppc64_rma_size - 1))

#endif /* __ASM_POWERPC_CRASHDUMP_PPC64_H */
