/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright 2020, Madhavan Srinivasan, IBM Corp.
 */

#ifndef _SELFTESTS_POWERPC_PMU_IMC_IMC_H
#define _SELFTESTS_POWERPC_PMU_IMC_IMC_H

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

#include "../event.h"
#include "../lib.h"


enum MEM_COUNTERS_DEV_TYPE{
	THREAD = 0x1,
	TRACE,
	CORE,
	HV_24X7,
};

extern bool is_mem_counters_device_enabled(int dtype);
extern int get_mem_counters_pmu_type_val(int dtype);
extern int setup_mem_counters_event(int dtype, struct event *e, u64 config, char *name);

#endif /* _SELFTESTS_POWERPC_PMU_IMC_IMC_H */
