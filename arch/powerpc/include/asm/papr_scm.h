/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Structures and defines needed to manage nvdimms for spapr guests.
 */
#ifndef _ASM_POWERPC_PAPR_SCM_H_
#define _ASM_POWERPC_PAPR_SCM_H_

#include <linux/types.h>
#include <asm/bitsperlong.h>

/* DIMM health bitmap bitmap indicators */

/* SCM device is unable to persist memory contents */
#define PAPR_SCM_DIMM_UNARMED                   (1ULL << (63 - 0))
/* SCM device failed to persist memory contents */
#define PAPR_SCM_DIMM_SHUTDOWN_DIRTY            (1ULL << (63 - 1))
/* SCM device contents are persisted from previous IPL */
#define PAPR_SCM_DIMM_SHUTDOWN_CLEAN            (1ULL << (63 - 2))
/* SCM device contents are not persisted from previous IPL */
#define PAPR_SCM_DIMM_EMPTY                     (1ULL << (63 - 3))
/* SCM device memory life remaining is critically low */
#define PAPR_SCM_DIMM_HEALTH_CRITICAL           (1ULL << (63 - 4))
/* SCM device will be garded off next IPL due to failure */
#define PAPR_SCM_DIMM_HEALTH_FATAL              (1ULL << (63 - 5))
/* SCM contents cannot persist due to current platform health status */
#define PAPR_SCM_DIMM_HEALTH_UNHEALTHY          (1ULL << (63 - 6))
/* SCM device is unable to persist memory contents in certain conditions */
#define PAPR_SCM_DIMM_HEALTH_NON_CRITICAL       (1ULL << (63 - 7))
/* SCM device is encrypted */
#define PAPR_SCM_DIMM_ENCRYPTED                 (1ULL << (63 - 8))
/* SCM device has been scrubbed and locked */
#define PAPR_SCM_DIMM_SCRUBBED_AND_LOCKED       (1ULL << (63 - 9))

/* Bits status indicators for health bitmap indicating unarmed dimm */
#define PAPR_SCM_DIMM_UNARMED_MASK (PAPR_SCM_DIMM_UNARMED |	\
					PAPR_SCM_DIMM_HEALTH_UNHEALTHY)

/* Bits status indicators for health bitmap indicating unflushed dimm */
#define PAPR_SCM_DIMM_BAD_SHUTDOWN_MASK (PAPR_SCM_DIMM_SHUTDOWN_DIRTY)

/* Bits status indicators for health bitmap indicating unrestored dimm */
#define PAPR_SCM_DIMM_BAD_RESTORE_MASK  (PAPR_SCM_DIMM_EMPTY)

/* Bit status indicators for smart event notification */
#define PAPR_SCM_DIMM_SMART_EVENT_MASK (PAPR_SCM_DIMM_HEALTH_CRITICAL | \
					   PAPR_SCM_DIMM_HEALTH_FATAL | \
					   PAPR_SCM_DIMM_HEALTH_UNHEALTHY)

#endif
