// SPDX-License-Id
// Copyright 2019 IBM Corp.

/*
 * A driver for OpenCAPI devices that implement the Storage Class
 * Memory specification.
 */

#include <linux/module.h>
#include <misc/ocxl.h>
#include <linux/delay.h>
#include <linux/ndctl.h>
#include <linux/mm_types.h>
#include <linux/memory_hotplug.h>
#include "ocxl_internal.h"


static const struct pci_device_id ocxlpmem_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0625), },
	{ }
};

MODULE_DEVICE_TABLE(pci, ocxlpmem_pci_tbl);

#define NUM_MINORS 256 // Total to reserve

static dev_t ocxlpmem_dev;
static struct class *ocxlpmem_class;
static struct mutex minors_idr_lock;
static struct idr minors_idr;

/**
 * ndctl_config_write() - Handle a ND_CMD_SET_CONFIG_DATA command from ndctl
 * @ocxlpmem: the device metadata
 * @command: the incoming data to write
 * Return: 0 on success, negative on failure
 */
static int ndctl_config_write(struct ocxlpmem *ocxlpmem,
			      struct nd_cmd_set_config_hdr *command)
{
	if (command->in_offset + command->in_length > LABEL_AREA_SIZE)
		return -EINVAL;

	memcpy_flushcache(ocxlpmem->metadata_addr + command->in_offset, command->in_buf,
			  command->in_length);

	return 0;
}

/**
 * ndctl_config_read() - Handle a ND_CMD_GET_CONFIG_DATA command from ndctl
 * @ocxlpmem: the device metadata
 * @command: the read request
 * Return: 0 on success, negative on failure
 */
static int ndctl_config_read(struct ocxlpmem *ocxlpmem,
			     struct nd_cmd_get_config_data_hdr *command)
{
	if (command->in_offset + command->in_length > LABEL_AREA_SIZE)
		return -EINVAL;

	memcpy_mcsafe(command->out_buf, ocxlpmem->metadata_addr + command->in_offset,
		      command->in_length);

	return 0;
}

/**
 * ndctl_config_size() - Handle a ND_CMD_GET_CONFIG_SIZE command from ndctl
 * @command: the read request
 * Return: 0 on success, negative on failure
 */
static int ndctl_config_size(struct nd_cmd_get_config_size *command)
{
	command->status = 0;
	command->config_size = LABEL_AREA_SIZE;
	command->max_xfer = PAGE_SIZE;

	return 0;
}

static int ndctl(struct nvdimm_bus_descriptor *nd_desc,
		 struct nvdimm *nvdimm,
		 unsigned int cmd, void *buf, unsigned int buf_len, int *cmd_rc)
{
	struct ocxlpmem *ocxlpmem = container_of(nd_desc, struct ocxlpmem, bus_desc);

	switch (cmd) {
	case ND_CMD_GET_CONFIG_SIZE:
		*cmd_rc = ndctl_config_size(buf);
		return 0;

	case ND_CMD_GET_CONFIG_DATA:
		*cmd_rc = ndctl_config_read(ocxlpmem, buf);
		return 0;

	case ND_CMD_SET_CONFIG_DATA:
		*cmd_rc = ndctl_config_write(ocxlpmem, buf);
		return 0;

	default:
		return -ENOTTY;
	}
}

/**
 * reserve_metadata() - Reserve space for nvdimm metadata
 * @ocxlpmem: the device metadata
 * @lpc_mem: The resource representing the LPC memory of the OpenCAPI device
 */
static int reserve_metadata(struct ocxlpmem *ocxlpmem,
			    struct resource *lpc_mem)
{
	ocxlpmem->metadata_addr = devm_memremap(&ocxlpmem->dev, lpc_mem->start,
						LABEL_AREA_SIZE, MEMREMAP_WB);
	if (IS_ERR(ocxlpmem->metadata_addr))
		return PTR_ERR(ocxlpmem->metadata_addr);

	return 0;
}

/**
 * register_lpc_mem() - Discover persistent memory on a device and register it with the NVDIMM subsystem
 * @ocxlpmem: the device metadata
 * Return: 0 on success
 */
static int register_lpc_mem(struct ocxlpmem *ocxlpmem)
{
	struct nd_region_desc region_desc;
	struct nd_mapping_desc nd_mapping_desc;
	struct resource *lpc_mem;
	const struct ocxl_afu_config *config;
	const struct ocxl_fn_config *fn_config;
	int rc;
	unsigned long nvdimm_cmd_mask = 0;
	unsigned long nvdimm_flags = 0;
	int target_node;
	char serial[16+1];

	// Set up the reserved metadata area
	rc = ocxl_afu_map_lpc_mem(ocxlpmem->ocxl_afu);
	if (rc < 0)
		return rc;

	lpc_mem = ocxl_afu_lpc_mem(ocxlpmem->ocxl_afu);
	if (lpc_mem == NULL || lpc_mem->start == 0)
		return -EINVAL;

	config = ocxl_afu_config(ocxlpmem->ocxl_afu);
	fn_config = ocxl_function_config(ocxlpmem->ocxl_fn);

	rc = reserve_metadata(ocxlpmem, lpc_mem);
	if (rc)
		return rc;

	ocxlpmem->bus_desc.provider_name = "ocxl-pmem";
	ocxlpmem->bus_desc.ndctl = ndctl;
	ocxlpmem->bus_desc.module = THIS_MODULE;

	ocxlpmem->nvdimm_bus = nvdimm_bus_register(&ocxlpmem->dev,
						   &ocxlpmem->bus_desc);
	if (!ocxlpmem->nvdimm_bus)
		return -EINVAL;

	ocxlpmem->pmem_res.start = (u64)lpc_mem->start + LABEL_AREA_SIZE;
	ocxlpmem->pmem_res.end = (u64)lpc_mem->start + config->lpc_mem_size - 1;
	ocxlpmem->pmem_res.name = "OpenCAPI persistent memory";

	set_bit(ND_CMD_GET_CONFIG_SIZE, &nvdimm_cmd_mask);
	set_bit(ND_CMD_GET_CONFIG_DATA, &nvdimm_cmd_mask);
	set_bit(ND_CMD_SET_CONFIG_DATA, &nvdimm_cmd_mask);

	set_bit(NDD_ALIASING, &nvdimm_flags);

	snprintf(serial, sizeof(serial), "%llx", fn_config->serial);
	nd_mapping_desc.nvdimm = nvdimm_create(ocxlpmem->nvdimm_bus, ocxlpmem,
				 NULL, nvdimm_flags, nvdimm_cmd_mask,
				 0, NULL);
	if (!nd_mapping_desc.nvdimm)
		return -ENOMEM;

	if (nvdimm_bus_check_dimm_count(ocxlpmem->nvdimm_bus, 1))
		return -EINVAL;

	nd_mapping_desc.start = ocxlpmem->pmem_res.start;
	nd_mapping_desc.size = resource_size(&ocxlpmem->pmem_res);
	nd_mapping_desc.position = 0;

	ocxlpmem->nd_set.cookie1 = fn_config->serial + 1; // allow for empty serial
	ocxlpmem->nd_set.cookie2 = fn_config->serial + 1;

	target_node = of_node_to_nid(ocxlpmem->pdev->dev.of_node);

	memset(&region_desc, 0, sizeof(region_desc));
	region_desc.res = &ocxlpmem->pmem_res;
	region_desc.numa_node = NUMA_NO_NODE;
	region_desc.target_node = target_node;
	region_desc.num_mappings = 1;
	region_desc.mapping = &nd_mapping_desc;
	region_desc.nd_set = &ocxlpmem->nd_set;

	set_bit(ND_REGION_PAGEMAP, &region_desc.flags);
	/*
	 * NB: libnvdimm copies the data from ndr_desc into it's own
	 * structures so passing a stack pointer is fine.
	 */
	ocxlpmem->nd_region = nvdimm_pmem_region_create(ocxlpmem->nvdimm_bus,
							&region_desc);
	if (!ocxlpmem->nd_region)
		return -EINVAL;

	dev_info(&ocxlpmem->dev,
		 "Onlining %lluMB of persistent memory\n",
		 nd_mapping_desc.size / SZ_1M);

	return 0;
}

/**
 * is_usable() - Is a controller usable?
 * @ocxlpmem: the device metadata
 * @verbose: True to log errors
 * Return: true if the controller is usable
 */
static bool is_usable(const struct ocxlpmem *ocxlpmem, bool verbose)
{
	u64 chi = 0;
	int rc = ocxlpmem_chi(ocxlpmem, &chi);

	if (rc < 0)
		return false;

	if (!(chi & GLOBAL_MMIO_CHI_CRDY)) {
		if (verbose)
			dev_err(&ocxlpmem->dev, "controller is not ready.\n");
		return false;
	}

	if (!(chi & GLOBAL_MMIO_CHI_MA)) {
		if (verbose)
			dev_err(&ocxlpmem->dev,
				"controller does not have memory available.\n");
		return false;
	}

	return true;
}

/**
 * allocate_minor() - Allocate a minor number to use for an OpenCAPI pmem device
 * @ocxlpmem: the device metadata
 * Return: the allocated minor number
 */
static int allocate_minor(struct ocxlpmem *ocxlpmem)
{
	int minor;

	mutex_lock(&minors_idr_lock);
	minor = idr_alloc(&minors_idr, ocxlpmem, 0, NUM_MINORS, GFP_KERNEL);
	mutex_unlock(&minors_idr_lock);
	return minor;
}

static void free_minor(struct ocxlpmem *ocxlpmem)
{
	mutex_lock(&minors_idr_lock);
	idr_remove(&minors_idr, MINOR(ocxlpmem->dev.devt));
	mutex_unlock(&minors_idr_lock);
}

/**
 * free_ocxlpmem() - Free all members of an ocxlpmem struct
 * @ocxlpmem: the device struct to clear
 */
static void free_ocxlpmem(struct ocxlpmem *ocxlpmem)
{
	int rc;

	if (ocxlpmem->nvdimm_bus)
		nvdimm_bus_unregister(ocxlpmem->nvdimm_bus);

	free_minor(ocxlpmem);

	if (ocxlpmem->metadata_addr)
		devm_memunmap(&ocxlpmem->dev, ocxlpmem->metadata_addr);

	if (ocxlpmem->ocxl_context) {
		rc = ocxl_context_detach(ocxlpmem->ocxl_context);
		if (rc == -EBUSY)
			dev_warn(&ocxlpmem->dev, "Timeout detaching ocxl context\n");
		else
			ocxl_context_free(ocxlpmem->ocxl_context);

	}

	if (ocxlpmem->ocxl_afu)
		ocxl_afu_put(ocxlpmem->ocxl_afu);

	if (ocxlpmem->ocxl_fn)
		ocxl_function_close(ocxlpmem->ocxl_fn);

	kfree(ocxlpmem);
}

/**
 * free_ocxlpmem_dev() - Free an OpenCAPI persistent memory device
 * @dev: The device struct
 */
static void free_ocxlpmem_dev(struct device *dev)
{
	struct ocxlpmem *ocxlpmem = container_of(dev, struct ocxlpmem, dev);

	free_ocxlpmem(ocxlpmem);
}

/**
 * ocxlpmem_register() - Register an OpenCAPI pmem device with the kernel
 * @ocxlpmem: the device metadata
 * Return: 0 on success, negative on failure
 */
static int ocxlpmem_register(struct ocxlpmem *ocxlpmem)
{
	int rc;
	int minor = allocate_minor(ocxlpmem);

	if (minor < 0)
		return minor;

	ocxlpmem->dev.release = free_ocxlpmem_dev;
	rc = dev_set_name(&ocxlpmem->dev, "ocxlpmem%d", minor);
	if (rc < 0)
		return rc;

	ocxlpmem->dev.devt = MKDEV(MAJOR(ocxlpmem_dev), minor);
	ocxlpmem->dev.class = ocxlpmem_class;
	ocxlpmem->dev.parent = &ocxlpmem->pdev->dev;

	return device_register(&ocxlpmem->dev);
}

/**
 * ocxlpmem_remove() - Free an OpenCAPI persistent memory device
 * @pdev: the PCI device information struct
 */
static void ocxlpmem_remove(struct pci_dev *pdev)
{
	if (PCI_FUNC(pdev->devfn) == 0) {
		struct ocxlpmem_function0 *func0 = pci_get_drvdata(pdev);

		if (func0) {
			ocxl_function_close(func0->ocxl_fn);
			func0->ocxl_fn = NULL;
		}
	} else {
		struct ocxlpmem *ocxlpmem = pci_get_drvdata(pdev);

		if (ocxlpmem)
			device_unregister(&ocxlpmem->dev);
	}
}

/**
 * read_device_metadata() - Retrieve config information from the AFU and save it for future use
 * @ocxlpmem: the device metadata
 * Return: 0 on success, negative on failure
 */
static int read_device_metadata(struct ocxlpmem *ocxlpmem)
{
	u64 val;
	int rc;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_CCAP0,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	ocxlpmem->scm_revision = val & 0xFFFF;
	ocxlpmem->read_latency = (val >> 32) & 0xFF;
	ocxlpmem->readiness_timeout = (val >> 48) & 0x0F;
	ocxlpmem->memory_available_timeout = val >> 52;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_CCAP1,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	ocxlpmem->max_controller_dump_size = val & 0xFFFFFFFF;

	// Extract firmware version text
	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_FWVER,
				     OCXL_HOST_ENDIAN, (u64 *)ocxlpmem->fw_version);
	if (rc)
		return rc;

	ocxlpmem->fw_version[8] = '\0';

	dev_info(&ocxlpmem->dev,
		 "Firmware version '%s' SCM revision %d:%d\n", ocxlpmem->fw_version,
		 ocxlpmem->scm_revision >> 4, ocxlpmem->scm_revision & 0x0F);

	return 0;
}

/**
 * probe_function0() - Set up function 0 for an OpenCAPI persistent memory device
 * This is important as it enables templates higher than 0 across all other functions,
 * which in turn enables higher bandwidth accesses
 * @pdev: the PCI device information struct
 * Return: 0 on success, negative on failure
 */
static int probe_function0(struct pci_dev *pdev)
{
	struct ocxlpmem_function0 *func0 = NULL;
	struct ocxl_fn *fn;

	func0 = kzalloc(sizeof(*func0), GFP_KERNEL);
	if (!func0)
		return -ENOMEM;

	func0->pdev = pdev;
	fn = ocxl_function_open(pdev);
	if (IS_ERR(fn)) {
		kfree(func0);
		dev_err(&pdev->dev, "failed to open OCXL function\n");
		return PTR_ERR(fn);
	}
	func0->ocxl_fn = fn;

	pci_set_drvdata(pdev, func0);

	return 0;
}

/**
 * probe() - Init an OpenCAPI persistent memory device
 * @pdev: the PCI device information struct
 * @ent: The entry from ocxlpmem_pci_tbl
 * Return: 0 on success, negative on failure
 */
static int probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct ocxlpmem *ocxlpmem;
	int rc;
	u16 elapsed, timeout;

	if (PCI_FUNC(pdev->devfn) == 0)
		return probe_function0(pdev);
	else if (PCI_FUNC(pdev->devfn) != 1)
		return 0;

	ocxlpmem = kzalloc(sizeof(*ocxlpmem), GFP_KERNEL);
	if (!ocxlpmem) {
		dev_err(&pdev->dev, "Could not allocate OpenCAPI persistent memory metadata\n");
		rc = -ENOMEM;
		goto err;
	}
	ocxlpmem->pdev = pdev;

	pci_set_drvdata(pdev, ocxlpmem);

	ocxlpmem->ocxl_fn = ocxl_function_open(pdev);
	if (IS_ERR(ocxlpmem->ocxl_fn)) {
		kfree(ocxlpmem);
		pci_set_drvdata(pdev, NULL);
		dev_err(&pdev->dev, "failed to open OCXL function\n");
		rc = PTR_ERR(ocxlpmem->ocxl_fn);
		goto err;
	}

	ocxlpmem->ocxl_afu = ocxl_function_fetch_afu(ocxlpmem->ocxl_fn, 0);
	if (ocxlpmem->ocxl_afu == NULL) {
		dev_err(&pdev->dev, "Could not get OCXL AFU from function\n");
		rc = -ENXIO;
		goto err;
	}

	ocxl_afu_get(ocxlpmem->ocxl_afu);

	// Resources allocated below here are cleaned up in the release handler

	rc = ocxlpmem_register(ocxlpmem);
	if (rc) {
		dev_err(&pdev->dev, "Could not register OpenCAPI persistent memory device with the kernel\n");
		goto err;
	}

	rc = ocxl_context_alloc(&ocxlpmem->ocxl_context, ocxlpmem->ocxl_afu, NULL);
	if (rc) {
		dev_err(&pdev->dev, "Could not allocate OCXL context\n");
		goto err;
	}

	rc = ocxl_context_attach(ocxlpmem->ocxl_context, 0, NULL);
	if (rc) {
		dev_err(&pdev->dev, "Could not attach ocxl context\n");
		goto err;
	}

	if (read_device_metadata(ocxlpmem)) {
		dev_err(&pdev->dev, "Could not read metadata\n");
		goto err;
	}

	elapsed = 0;
	timeout = ocxlpmem->readiness_timeout + ocxlpmem->memory_available_timeout;
	while (!is_usable(ocxlpmem, false)) {
		if (elapsed++ > timeout) {
			dev_warn(&ocxlpmem->dev, "OpenCAPI Persistent Memory ready timeout.\n");
			(void)is_usable(ocxlpmem, true);
			rc = -ENXIO;
			goto err;
		}

		msleep(1000);
	}

	rc = register_lpc_mem(ocxlpmem);
	if (rc) {
		dev_err(&pdev->dev, "Could not register OpenCAPI persistent memory with libnvdimm\n");
		goto err;
	}

	return 0;

err:
	/*
	 * Further cleanup is done in the release handler via free_ocxlpmem()
	 * This allows us to keep the character device live to handle IOCTLs to
	 * investigate issues if the card has an error
	 */

	dev_err(&pdev->dev,
		"Error detected, will not register OpenCAPI persistent memory\n");
	return rc;
}

static struct pci_driver pci_driver = {
	.name = "ocxl-pmem",
	.id_table = ocxlpmem_pci_tbl,
	.probe = probe,
	.remove = ocxlpmem_remove,
	.shutdown = ocxlpmem_remove,
};

static int __init ocxlpmem_init(void)
{
	int rc = 0;

	rc = pci_register_driver(&pci_driver);
	if (rc)
		return rc;

	return 0;
}

static void ocxlpmem_exit(void)
{
	pci_unregister_driver(&pci_driver);
}

module_init(ocxlpmem_init);
module_exit(ocxlpmem_exit);

MODULE_DESCRIPTION("OpenCAPI Persistent Memory");
MODULE_LICENSE("GPL");
