// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2020, Madhavan Srinivasan, IBM Corp.
 */

#include "mem_counters.h"

static  bool check_imc_interface_glob_lck(void)
{
	if (!access("/sys/devices/thread_imc/interface/glob_lck", F_OK))
		return true;

	return false;
}

static int testcase(void)
{
	struct event events[2];

	if (!check_imc_interface_glob_lck()) {
		printf("Test not supported\n");
		return MAGIC_SKIP_RETURN_VALUE;
	}

	if (!is_mem_counters_device_enabled(CORE) || !is_mem_counters_device_enabled(THREAD)) {
		printf("%s: IMC device not found. So exiting the test\n", __FUNCTION__);
		return -1;
	}

	if (setup_mem_counters_event(THREAD, &events[0], 0xe0, "thread_imc/cycles")) {
		printf("%s setup_mem_counters_event for thread_imc failed\n", __FUNCTION__);
		return -1;
	}

	if (setup_mem_counters_event(CORE, &events[1], 0xe0, "core_imc/cycles")) {
		printf("%s setup_mem_counters_event for core_imc failed\n", __FUNCTION__);
		return -1;
	}

	if (event_open(&events[0])) {
		perror("thread_imc: perf_event_open");
		return -1;
	}

	/*
	 * If we have the Global lock patchset applied to kernel
	 * event_open for events[1] should fail with resource busy
	 */
	if (event_open_with_cpu(&events[1], 0)) {
		/*
		 * Check for the errno to certify the test result
		 */
		if (errno == 16) // Resource busy (EBUSY)
			return 0;
	}

	return -1;
}

static int imc_global_lock_test(void)
{
	return eat_cpu(testcase);
}

int main(void)
{
	return test_harness(imc_global_lock_test, "imc_global_lock_test");
}
