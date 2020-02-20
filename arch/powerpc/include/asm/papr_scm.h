/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Structures and defines needed to manage nvdimms for spapr guests.
 */
#ifndef _ASM_POWERPC_PAPR_SCM_H_
#define _ASM_POWERPC_PAPR_SCM_H_

#include <linux/types.h>
#include <asm/bitsperlong.h>
#include <linux/stringify.h>

/* DIMM health bitmap bitmap indicators */
/* SCM device is unable to persist memory contents */
#define PAPR_SCM_DIMM_UNARMED			PPC_BIT(0)
/* SCM device failed to persist memory contents */
#define PAPR_SCM_DIMM_SHUTDOWN_DIRTY		PPC_BIT(1)
/* SCM device contents are persisted from previous IPL */
#define PAPR_SCM_DIMM_SHUTDOWN_CLEAN		PPC_BIT(2)
/* SCM device contents are not persisted from previous IPL */
#define PAPR_SCM_DIMM_EMPTY			PPC_BIT(3)
/* SCM device memory life remaining is critically low */
#define PAPR_SCM_DIMM_HEALTH_CRITICAL		PPC_BIT(4)
/* SCM device will be garded off next IPL due to failure */
#define PAPR_SCM_DIMM_HEALTH_FATAL		PPC_BIT(5)
/* SCM contents cannot persist due to current platform health status */
#define PAPR_SCM_DIMM_HEALTH_UNHEALTHY		PPC_BIT(6)
/* SCM device is unable to persist memory contents in certain conditions */
#define PAPR_SCM_DIMM_HEALTH_NON_CRITICAL	PPC_BIT(7)
/* SCM device is encrypted */
#define PAPR_SCM_DIMM_ENCRYPTED			PPC_BIT(8)
/* SCM device has been scrubbed and locked */
#define PAPR_SCM_DIMM_SCRUBBED_AND_LOCKED	PPC_BIT(9)

/* Bits status indicators for health bitmap indicating unarmed dimm */
#define PAPR_SCM_DIMM_UNARMED_MASK (PAPR_SCM_DIMM_UNARMED |	\
					PAPR_SCM_DIMM_HEALTH_UNHEALTHY | \
					PAPR_SCM_DIMM_HEALTH_NON_CRITICAL)

/* Bits status indicators for health bitmap indicating unflushed dimm */
#define PAPR_SCM_DIMM_BAD_SHUTDOWN_MASK (PAPR_SCM_DIMM_SHUTDOWN_DIRTY)

/* Bits status indicators for health bitmap indicating unrestored dimm */
#define PAPR_SCM_DIMM_BAD_RESTORE_MASK  (PAPR_SCM_DIMM_EMPTY)

/* Bit status indicators for smart event notification */
#define PAPR_SCM_DIMM_SMART_EVENT_MASK (PAPR_SCM_DIMM_HEALTH_CRITICAL | \
					   PAPR_SCM_DIMM_HEALTH_FATAL | \
					   PAPR_SCM_DIMM_HEALTH_UNHEALTHY | \
					   PAPR_SCM_DIMM_HEALTH_NON_CRITICAL)

#define PAPR_SCM_PERF_STATS_EYECATCHER __stringify(SCMSTATS)

/* Struct holding a single performance metric */
struct papr_scm_perf_stat {
	__be64 statistic_id;
	__be64 statistic_value;
};

/* Struct exchanged between kernel and ndctl reporting drc perf stats */
struct papr_scm_perf_stats {
	uint8_t eye_catcher[8];
	__be32 stats_version;		/* Should be 0x01 */
	__be32 num_statistics;		/* Number of stats following */
	/* zero or more performance matrics */
	struct papr_scm_perf_stat scm_statistics[];
} __packed;

#endif
