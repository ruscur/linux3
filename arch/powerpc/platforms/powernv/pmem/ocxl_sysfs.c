// SPDX-License-Identifier: GPL-2.0+
// Copyright 2018 IBM Corp.

#include <linux/sysfs.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/firmware.h>
#include "ocxl_internal.h"

static ssize_t serial_show(struct device *device, struct device_attribute *attr,
			   char *buf)
{
	struct ocxlpmem *ocxlpmem = container_of(device, struct ocxlpmem, dev);
	const struct ocxl_fn_config *fn_config = ocxl_function_config(ocxlpmem->ocxl_fn);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", fn_config->serial);
}

static struct device_attribute attrs[] = {
	__ATTR_RO(serial),
};

int ocxlpmem_sysfs_add(struct ocxlpmem *ocxlpmem)
{
	int i, rc;

	for (i = 0; i < ARRAY_SIZE(attrs); i++) {
		rc = device_create_file(&ocxlpmem->dev, &attrs[i]);
		if (rc) {
			for (; --i >= 0;)
				device_remove_file(&ocxlpmem->dev, &attrs[i]);

			return rc;
		}
	}
	return 0;
}
