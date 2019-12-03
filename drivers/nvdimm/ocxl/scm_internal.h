// SPDX-License-Identifier: GPL-2.0+
// Copyright 2019 IBM Corp.

#include <linux/pci.h>
#include <misc/ocxl.h>
#include <linux/libnvdimm.h>
#include <linux/mm.h>

#define SCM_LABEL_AREA_SIZE	(1UL << PA_SECTION_SHIFT)

struct scm_function_0 {
	struct pci_dev *pdev;
	struct ocxl_fn *ocxl_fn;
};

struct scm_data {
	struct device dev;
	struct pci_dev *pdev;
	struct ocxl_fn *ocxl_fn;
	struct nd_interleave_set nd_set;
	struct nvdimm_bus_descriptor bus_desc;
	struct nvdimm_bus *nvdimm_bus;
	struct ocxl_afu *ocxl_afu;
	struct ocxl_context *ocxl_context;
	void *metadata_addr;
	struct resource scm_res;
	struct nd_region *nd_region;
};
