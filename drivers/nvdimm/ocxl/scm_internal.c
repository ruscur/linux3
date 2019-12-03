// SPDX-License-Identifier: GPL-2.0+
// Copyright 2019 IBM Corp.

#include <misc/ocxl.h>
#include <linux/delay.h>
#include "scm_internal.h"

int scm_chi(const struct scm_data *scm_data, u64 *chi)
{
	u64 val;
	int rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, GLOBAL_MMIO_CHI,
					 OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	*chi = val;

	return 0;
}
