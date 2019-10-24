// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 IBM Corporation
 * Author: Nayna Jain
 */
#include <linux/types.h>
#include <linux/of.h>
#include <asm/secure_boot.h>

bool is_ppc_secureboot_enabled(void)
{
	struct device_node *node;
	bool enabled = false;

	node = of_find_compatible_node(NULL, NULL, "ibm,secvar-v1");
	if (!of_device_is_available(node)) {
		pr_err("Cannot find secure variable node in device tree; failing to secure state\n");
		goto out;
	}

	/*
	 * secureboot is enabled if os-secure-enforcing property exists,
	 * else disabled.
	 */
	enabled = of_property_read_bool(node, "os-secure-enforcing");

out:
	of_node_put(node);

	pr_info("Secure boot mode %s\n", enabled ? "enabled" : "disabled");
	return enabled;
}
