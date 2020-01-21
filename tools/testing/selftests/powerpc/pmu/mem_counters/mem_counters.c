// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2020, Madhavan Srinivasan, IBM Corp.
 */

#include "mem_counters.h"

/*
 * mem_counters.c will contain common/basic functions
 * to support testcases for both In Memory Collection (IMC)
 * and hv_24x7 counters.
 */


/*
 * Since device type enum starts with 1,
 * have the first entry in the array as a placeholder.
 */
const char mem_counters_dev_path[][30] = {
	"",
	"/sys/devices/thread_imc",
	"/sys/devices/trace_imc",
	"/sys/devices/core_imc",
	"/sys/devices/hv_24x7",
	"",
};

const char mem_counters_dev_type_path[][35] = {
	"",
	"/sys/devices/thread_imc/type",
	"/sys/devices/trace_imc/type",
	"/sys/devices/core_imc/type",
	"/sys/devices/hv_24x7/type",
	"",
};


static bool is_mem_counters_dev_registered(int dtype)
{
	if (!access(mem_counters_dev_path[dtype], F_OK))
		return true;

	return false;
}

bool is_mem_counters_device_enabled(int dtype)
{
	switch (dtype) {
	case THREAD:
		if (is_mem_counters_dev_registered(THREAD))
			return true;
	case TRACE:
		if (is_mem_counters_dev_registered(TRACE))
			return true;
		break;
	case CORE:
		if (is_mem_counters_dev_registered(CORE))
			return true;
	case HV_24X7:
		if (is_mem_counters_dev_registered(HV_24X7))
			return true;
	};

	return false;
}

int get_mem_counters_pmu_type_val(int dtype)
{
	FILE *fp = NULL;
	char buf[10];
	int val;

	fp = fopen(mem_counters_dev_type_path[dtype], "r");
	if (!fp) {
		perror("Failed to open\n");
		return -1;
	}

	if (!fgets(buf, 10, fp)) {
		perror("Failed to read\n");
		return -1;
	}

	fclose(fp);
	val = atoi(buf);
	return val;
}

int setup_mem_counters_event(int dtype, struct event *e, u64 config, char *name)
{
	int val = get_mem_counters_pmu_type_val(dtype);

	if (val > 0) {
		event_init_opts(e, config, val, name);
		return 0;
	}

	return -1;
}
