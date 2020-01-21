// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2020, Madhavan Srinivasan, IBM Corp.
 */

#include "mem_counters.h"

static int testcase(void)
{
	return 0;
}

static int imc_global_lock_test(void)
{
	return eat_cpu(testcase);
}

int main(void)
{
	return test_harness(imc_global_lock_test, "imc_global_lock_test");
}
