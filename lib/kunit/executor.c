// SPDX-License-Identifier: GPL-2.0

#include <linux/reboot.h>
#include <kunit/test.h>

/*
 * These symbols point to the .kunit_test_suites section and are defined in
 * include/asm-generic/vmlinux.lds.h, and consequently must be extern.
 */
extern struct kunit_suite * const * const __kunit_suites_start[];
extern struct kunit_suite * const * const __kunit_suites_end[];

#if IS_BUILTIN(CONFIG_KUNIT)

static char *kunit_shutdown;
core_param(kunit_shutdown, kunit_shutdown, charp, 0644);

static void kunit_handle_shutdown(void)
{
	if (!kunit_shutdown)
		return;

	if (!strcmp(kunit_shutdown, "poweroff"))
		kernel_power_off();
	else if (!strcmp(kunit_shutdown, "halt"))
		kernel_halt();
	else if (!strcmp(kunit_shutdown, "reboot"))
		kernel_restart(NULL);

}

static void kunit_print_tap_header(void)
{
	struct kunit_suite * const * const *suites, * const *subsuite;
	int num_of_suites = 0;

	for (suites = __kunit_suites_start;
	     suites < __kunit_suites_end;
	     suites++)
		for (subsuite = *suites; *subsuite != NULL; subsuite++)
			num_of_suites++;

	pr_info("TAP version 14\n");
	pr_info("1..%d\n", num_of_suites);
}

int kunit_run_all_tests(void)
{
	struct kunit_suite * const * const *suites;

	kunit_print_tap_header();

	for (suites = __kunit_suites_start;
	     suites < __kunit_suites_end;
	     suites++)
			__kunit_test_suites_init(*suites);

	kunit_handle_shutdown();

	return 0;
}

#endif /* IS_BUILTIN(CONFIG_KUNIT) */
