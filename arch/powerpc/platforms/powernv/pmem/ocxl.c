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
#include <linux/eventfd.h>
#include <linux/fs.h>
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
 * extract_command_metadata() - Extract command data from MMIO & save it for further use
 * @ocxlpmem: the device metadata
 * @offset: The base address of the command data structures (address of CREQO)
 * @command_metadata: A pointer to the command metadata to populate
 * Return: 0 on success, negative on failure
 */
static int extract_command_metadata(struct ocxlpmem *ocxlpmem, u32 offset,
					struct command_metadata *command_metadata)
{
	int rc;
	u64 tmp;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu, offset, OCXL_LITTLE_ENDIAN,
				     &tmp);
	if (rc)
		return rc;

	command_metadata->request_offset = tmp >> 32;
	command_metadata->response_offset = tmp & 0xFFFFFFFF;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu, offset + 8, OCXL_LITTLE_ENDIAN,
				     &tmp);
	if (rc)
		return rc;

	command_metadata->data_offset = tmp >> 32;
	command_metadata->data_size = tmp & 0xFFFFFFFF;

	command_metadata->id = 0;

	return 0;
}

/**
 * setup_command_metadata() - Set up the command metadata
 * @ocxlpmem: the device metadata
 */
static int setup_command_metadata(struct ocxlpmem *ocxlpmem)
{
	int rc;

	mutex_init(&ocxlpmem->admin_command.lock);
	mutex_init(&ocxlpmem->ns_command.lock);

	rc = extract_command_metadata(ocxlpmem, GLOBAL_MMIO_ACMA_CREQO,
				      &ocxlpmem->admin_command);
	if (rc)
		return rc;

	rc = extract_command_metadata(ocxlpmem, GLOBAL_MMIO_NSCMA_CREQO,
					  &ocxlpmem->ns_command);
	if (rc)
		return rc;

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

	// Disable doorbells
	(void)ocxl_global_mmio_set64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_CHIEC,
				     OCXL_LITTLE_ENDIAN,
				     GLOBAL_MMIO_CHI_ALL);

	if (ocxlpmem->nvdimm_bus)
		nvdimm_bus_unregister(ocxlpmem->nvdimm_bus);

	free_minor(ocxlpmem);

	if (ocxlpmem->irq_addr[1])
		iounmap(ocxlpmem->irq_addr[1]);

	if (ocxlpmem->irq_addr[0])
		iounmap(ocxlpmem->irq_addr[0]);

	if (ocxlpmem->cdev.owner)
		cdev_del(&ocxlpmem->cdev);

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

static void ocxlpmem_put(struct ocxlpmem *ocxlpmem)
{
	put_device(&ocxlpmem->dev);
}

static struct ocxlpmem *ocxlpmem_get(struct ocxlpmem *ocxlpmem)
{
	return (get_device(&ocxlpmem->dev) == NULL) ? NULL : ocxlpmem;
}

static struct ocxlpmem *find_and_get_ocxlpmem(dev_t devno)
{
	struct ocxlpmem *ocxlpmem;
	int minor = MINOR(devno);
	/*
	 * We don't declare an RCU critical section here, as our AFU
	 * is protected by a reference counter on the device. By the time the
	 * minor number of a device is removed from the idr, the ref count of
	 * the device is already at 0, so no user API will access that AFU and
	 * this function can't return it.
	 */
	ocxlpmem = idr_find(&minors_idr, minor);
	if (ocxlpmem)
		ocxlpmem_get(ocxlpmem);
	return ocxlpmem;
}

static int file_open(struct inode *inode, struct file *file)
{
	struct ocxlpmem *ocxlpmem;

	ocxlpmem = find_and_get_ocxlpmem(inode->i_rdev);
	if (!ocxlpmem)
		return -ENODEV;

	file->private_data = ocxlpmem;
	return 0;
}

static int file_release(struct inode *inode, struct file *file)
{
	struct ocxlpmem *ocxlpmem = file->private_data;

	if (ocxlpmem->ev_ctx) {
		eventfd_ctx_put(ocxlpmem->ev_ctx);
		ocxlpmem->ev_ctx = NULL;
	}

	ocxlpmem_put(ocxlpmem);
	return 0;
}

/**
 * error_log_header_parse() - Parse the first 64 bits of the error log command response
 * @ocxlpmem: the device metadata
 * @length: out, returns the number of bytes in the response (excluding the 64 bit header)
 */
static int error_log_header_parse(struct ocxlpmem *ocxlpmem, u16 *length)
{
	int rc;
	u64 val;

	u16 data_identifier;
	u32 data_length;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	data_identifier = val >> 48;
	data_length = val & 0xFFFF;

	if (data_identifier != 0x454C) { // 'EL'
		dev_err(&ocxlpmem->dev,
			"Bad data identifier for error log data, expected 'EL', got '%2s' (%#x), data_length=%u\n",
			(char *)&data_identifier,
			(unsigned int)data_identifier, data_length);
		return -EINVAL;
	}

	*length = data_length;
	return 0;
}

static int error_log_offset_0x08(struct ocxlpmem *ocxlpmem,
				 u32 *log_identifier, u32 *program_ref_code)
{
	int rc;
	u64 val;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	*log_identifier = val >> 32;
	*program_ref_code = val & 0xFFFFFFFF;

	return 0;
}

static int read_error_log(struct ocxlpmem *ocxlpmem,
			  struct ioctl_ocxl_pmem_error_log *log, bool buf_is_user)
{
	u64 val;
	u16 user_buf_length;
	u16 buf_length;
	u16 i;
	int rc;

	if (log->buf_size % 8)
		return -EINVAL;

	rc = ocxlpmem_chi(ocxlpmem, &val);
	if (rc)
		goto out;

	if (!(val & GLOBAL_MMIO_CHI_ELA))
		return -EAGAIN;

	user_buf_length = log->buf_size;

	mutex_lock(&ocxlpmem->admin_command.lock);

	rc = admin_command_request(ocxlpmem, ADMIN_COMMAND_ERRLOG);
	if (rc)
		goto out;

	rc = admin_command_execute(ocxlpmem);
	if (rc)
		goto out;

	rc = admin_command_complete_timeout(ocxlpmem, ADMIN_COMMAND_ERRLOG);
	if (rc < 0) {
		dev_warn(&ocxlpmem->dev, "Read error log timed out\n");
		goto out;
	}

	rc = admin_response(ocxlpmem);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS) {
		warn_status(ocxlpmem, "Unexpected status from retrieve error log", rc);
		goto out;
	}


	rc = error_log_header_parse(ocxlpmem, &log->buf_size);
	if (rc)
		goto out;
	// log->buf_size now contains the returned buffer size, not the user size

	rc = error_log_offset_0x08(ocxlpmem, &log->log_identifier,
				       &log->program_reference_code);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x10,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		goto out;

	log->error_log_type = val >> 56;
	log->action_flags = (log->error_log_type == OCXL_PMEM_ERROR_LOG_TYPE_GENERAL) ?
			    (val >> 32) & 0xFFFFFF : 0;
	log->power_on_seconds = val & 0xFFFFFFFF;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x18,
				     OCXL_LITTLE_ENDIAN, &log->timestamp);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x20,
				     OCXL_HOST_ENDIAN, &log->wwid[0]);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x28,
				     OCXL_HOST_ENDIAN, &log->wwid[1]);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x30,
				     OCXL_HOST_ENDIAN, (u64 *)log->fw_revision);
	if (rc)
		goto out;
	log->fw_revision[8] = '\0';

	buf_length = (user_buf_length < log->buf_size) ?
		     user_buf_length : log->buf_size;
	for (i = 0; i < buf_length + 0x48; i += 8) {
		u64 val;

		rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
					     ocxlpmem->admin_command.data_offset + i,
					     OCXL_HOST_ENDIAN, &val);
		if (rc)
			goto out;

		if (buf_is_user) {
			if (copy_to_user(&log->buf[i], &val, sizeof(u64))) {
				rc = -EFAULT;
				goto out;
			}
		} else
			log->buf[i] = val;
	}

	rc = admin_response_handled(ocxlpmem);
	if (rc)
		goto out;

out:
	mutex_unlock(&ocxlpmem->admin_command.lock);
	return rc;

}

static int ioctl_error_log(struct ocxlpmem *ocxlpmem,
		struct ioctl_ocxl_pmem_error_log __user *uarg)
{
	struct ioctl_ocxl_pmem_error_log args;
	int rc;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	rc = read_error_log(ocxlpmem, &args, true);
	if (rc)
		return rc;

	if (copy_to_user(uarg, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static int ioctl_controller_dump_data(struct ocxlpmem *ocxlpmem,
		struct ioctl_ocxl_pmem_controller_dump_data __user *uarg)
{
	struct ioctl_ocxl_pmem_controller_dump_data args;
	u16 i;
	u64 val;
	int rc;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	if (args.buf_size % 8)
		return -EINVAL;

	if (args.buf_size > ocxlpmem->admin_command.data_size)
		return -EINVAL;

	mutex_lock(&ocxlpmem->admin_command.lock);

	rc = admin_command_request(ocxlpmem, ADMIN_COMMAND_CONTROLLER_DUMP);
	if (rc)
		goto out;

	val = ((u64)args.offset) << 32;
	val |= args.buf_size;
	rc = ocxl_global_mmio_write64(ocxlpmem->ocxl_afu,
				      ocxlpmem->admin_command.request_offset + 0x08,
				      OCXL_LITTLE_ENDIAN, val);
	if (rc)
		goto out;

	rc = admin_command_execute(ocxlpmem);
	if (rc)
		goto out;

	rc = admin_command_complete_timeout(ocxlpmem,
					    ADMIN_COMMAND_CONTROLLER_DUMP);
	if (rc < 0) {
		dev_warn(&ocxlpmem->dev, "Controller dump timed out\n");
		goto out;
	}

	rc = admin_response(ocxlpmem);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS) {
		warn_status(ocxlpmem,
			    "Unexpected status from retrieve error log",
			    rc);
		goto out;
	}

	for (i = 0; i < args.buf_size; i += 8) {
		u64 val;

		rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
					     ocxlpmem->admin_command.data_offset + i,
					     OCXL_HOST_ENDIAN, &val);
		if (rc)
			goto out;

		if (copy_to_user(&args.buf[i], &val, sizeof(u64))) {
			rc = -EFAULT;
			goto out;
		}
	}

	if (copy_to_user(uarg, &args, sizeof(args))) {
		rc = -EFAULT;
		goto out;
	}

	rc = admin_response_handled(ocxlpmem);
	if (rc)
		goto out;

out:
	mutex_unlock(&ocxlpmem->admin_command.lock);
	return rc;
}

int request_controller_dump(struct ocxlpmem *ocxlpmem)
{
	int rc;
	u64 busy = 1;

	rc = ocxl_global_mmio_set64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_CHIC,
				    OCXL_LITTLE_ENDIAN,
				    GLOBAL_MMIO_CHI_CDA);


	rc = ocxl_global_mmio_set64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_HCI,
				    OCXL_LITTLE_ENDIAN,
				    GLOBAL_MMIO_HCI_CONTROLLER_DUMP);
	if (rc)
		return rc;

	while (busy) {
		rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
					     GLOBAL_MMIO_HCI,
					     OCXL_LITTLE_ENDIAN, &busy);
		if (rc)
			return rc;

		busy &= GLOBAL_MMIO_HCI_CONTROLLER_DUMP;
		cond_resched();
	}

	return 0;
}

static int ioctl_controller_dump_complete(struct ocxlpmem *ocxlpmem)
{
	return ocxl_global_mmio_set64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_HCI,
				    OCXL_LITTLE_ENDIAN,
				    GLOBAL_MMIO_HCI_CONTROLLER_DUMP_COLLECTED);
}

/**
 * controller_stats_header_parse() - Parse the first 64 bits of the controller stats admin command response
 * @ocxlpmem: the device metadata
 * @length: out, returns the number of bytes in the response (excluding the 64 bit header)
 */
static int controller_stats_header_parse(struct ocxlpmem *ocxlpmem,
	u32 *length)
{
	int rc;
	u64 val;

	u16 data_identifier;
	u32 data_length;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	data_identifier = val >> 48;
	data_length = val & 0xFFFFFFFF;

	if (data_identifier != 0x4353) { // 'CS'
		dev_err(&ocxlpmem->dev,
			"Bad data identifier for controller stats, expected 'CS', got '%-.*s'\n",
			2, (char *)&data_identifier);
		return -EINVAL;
	}

	*length = data_length;
	return 0;
}

static int ioctl_controller_stats(struct ocxlpmem *ocxlpmem,
				  struct ioctl_ocxl_pmem_controller_stats __user *uarg)
{
	struct ioctl_ocxl_pmem_controller_stats args;
	u32 length;
	int rc;
	u64 val;

	memset(&args, '\0', sizeof(args));

	mutex_lock(&ocxlpmem->admin_command.lock);

	rc = admin_command_request(ocxlpmem, ADMIN_COMMAND_CONTROLLER_STATS);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_write64(ocxlpmem->ocxl_afu,
				      ocxlpmem->admin_command.request_offset + 0x08,
				      OCXL_LITTLE_ENDIAN, 0);
	if (rc)
		goto out;

	rc = admin_command_execute(ocxlpmem);
	if (rc)
		goto out;


	rc = admin_command_complete_timeout(ocxlpmem,
					    ADMIN_COMMAND_CONTROLLER_STATS);
	if (rc < 0) {
		dev_warn(&ocxlpmem->dev, "Controller stats timed out\n");
		goto out;
	}

	rc = admin_response(ocxlpmem);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS) {
		warn_status(ocxlpmem,
			    "Unexpected status from controller stats", rc);
		goto out;
	}

	rc = controller_stats_header_parse(ocxlpmem, &length);
	if (rc)
		goto out;

	if (length != 0x140)
		warn_status(ocxlpmem,
			    "Unexpected length for controller stats data, expected 0x140, got 0x%x",
			    length);

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x08,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		goto out;

	args.reset_count = val >> 32;
	args.reset_uptime = val & 0xFFFFFFFF;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x10,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		goto out;

	args.power_on_uptime = val >> 32;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x08,
				     OCXL_LITTLE_ENDIAN, &args.host_load_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x10,
				     OCXL_LITTLE_ENDIAN, &args.host_store_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x18,
				     OCXL_LITTLE_ENDIAN, &args.media_read_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x20,
				     OCXL_LITTLE_ENDIAN, &args.media_write_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x28,
				     OCXL_LITTLE_ENDIAN, &args.cache_hit_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x30,
				     OCXL_LITTLE_ENDIAN, &args.cache_miss_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x38,
				     OCXL_LITTLE_ENDIAN, &args.media_read_latency);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x40,
				     OCXL_LITTLE_ENDIAN, &args.media_write_latency);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x48,
				     OCXL_LITTLE_ENDIAN, &args.cache_read_latency);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(ocxlpmem->ocxl_afu,
				     ocxlpmem->admin_command.data_offset + 0x08 + 0x40 + 0x50,
				     OCXL_LITTLE_ENDIAN, &args.cache_write_latency);
	if (rc)
		goto out;

	if (copy_to_user(uarg, &args, sizeof(args))) {
		rc = -EFAULT;
		goto out;
	}

	rc = admin_response_handled(ocxlpmem);
	if (rc)
		goto out;

	rc = 0;
	goto out;

out:
	mutex_unlock(&ocxlpmem->admin_command.lock);
	return rc;
}

static int ioctl_eventfd(struct ocxlpmem *ocxlpmem,
		 struct ioctl_ocxl_pmem_eventfd __user *uarg)
{
	struct ioctl_ocxl_pmem_eventfd args;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	if (ocxlpmem->ev_ctx)
		return -EINVAL;

	ocxlpmem->ev_ctx = eventfd_ctx_fdget(args.eventfd);
	if (!ocxlpmem->ev_ctx)
		return -EFAULT;

	return 0;
}

static int ioctl_event_check(struct ocxlpmem *ocxlpmem, u64 __user *uarg)
{
	u64 val = 0;
	int rc;
	u64 chi = 0;

	rc = ocxlpmem_chi(ocxlpmem, &chi);
	if (rc < 0)
		return rc;

	if (chi & GLOBAL_MMIO_CHI_ELA)
		val |= IOCTL_OCXL_PMEM_EVENT_ERROR_LOG_AVAILABLE;

	if (chi & GLOBAL_MMIO_CHI_CDA)
		val |= IOCTL_OCXL_PMEM_EVENT_CONTROLLER_DUMP_AVAILABLE;

	if (chi & GLOBAL_MMIO_CHI_CFFS)
		val |= IOCTL_OCXL_PMEM_EVENT_FIRMWARE_FATAL;

	if (chi & GLOBAL_MMIO_CHI_CHFS)
		val |= IOCTL_OCXL_PMEM_EVENT_HARDWARE_FATAL;

	rc = copy_to_user((u64 __user *) uarg, &val, sizeof(val));

	return rc;
}

static long file_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	struct ocxlpmem *ocxlpmem = file->private_data;
	int rc = -EINVAL;

	switch (cmd) {
	case IOCTL_OCXL_PMEM_ERROR_LOG:
		rc = ioctl_error_log(ocxlpmem,
				     (struct ioctl_ocxl_pmem_error_log __user *)args);
		break;

	case IOCTL_OCXL_PMEM_CONTROLLER_DUMP:
		rc = request_controller_dump(ocxlpmem);
		break;

	case IOCTL_OCXL_PMEM_CONTROLLER_DUMP_DATA:
		rc = ioctl_controller_dump_data(ocxlpmem,
						(struct ioctl_ocxl_pmem_controller_dump_data __user *)args);
		break;

	case IOCTL_OCXL_PMEM_CONTROLLER_DUMP_COMPLETE:
		rc = ioctl_controller_dump_complete(ocxlpmem);
		break;

	case IOCTL_OCXL_PMEM_CONTROLLER_STATS:
		rc = ioctl_controller_stats(ocxlpmem,
					    (struct ioctl_ocxl_pmem_controller_stats __user *)args);
		break;

	case IOCTL_OCXL_PMEM_EVENTFD:
		rc = ioctl_eventfd(ocxlpmem,
				   (struct ioctl_ocxl_pmem_eventfd __user *)args);
		break;

	case IOCTL_OCXL_PMEM_EVENT_CHECK:
		rc = ioctl_event_check(ocxlpmem, (u64 __user *)args);
		break;
	}

	return rc;
}

static const struct file_operations fops = {
	.owner		= THIS_MODULE,
	.open		= file_open,
	.release	= file_release,
	.unlocked_ioctl = file_ioctl,
	.compat_ioctl   = file_ioctl,
};

/**
 * create_cdev() - Create the chardev in /dev for the device
 * @ocxlpmem: the SCM metadata
 * Return: 0 on success, negative on failure
 */
static int create_cdev(struct ocxlpmem *ocxlpmem)
{
	cdev_init(&ocxlpmem->cdev, &fops);
	return cdev_add(&ocxlpmem->cdev, ocxlpmem->dev.devt, 1);
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

static const char *decode_error_log_type(u8 error_log_type)
{
	switch (error_log_type) {
	case 0x00:
		return "general";
	case 0x01:
		return "predictive failure";
	case 0x02:
		return "thermal warning";
	case 0x03:
		return "data loss";
	case 0x04:
		return "health & performance";
	default:
		return "unknown";
	}
}

static void dump_error_log(struct ocxlpmem *ocxlpmem)
{
	struct ioctl_ocxl_pmem_error_log log;
	u32 buf_size;
	u8 *buf;
	int rc;

	if (ocxlpmem->admin_command.data_size == 0)
		return;

	buf_size = ocxlpmem->admin_command.data_size - 0x48;
	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return;

	log.buf = buf;
	log.buf_size = buf_size;

	rc = read_error_log(ocxlpmem, &log, false);
	if (rc < 0)
		goto out;

	dev_warn(&ocxlpmem->dev,
		 "OCXL PMEM Error log: WWID=0x%016llx%016llx LID=0x%x PRC=%x type=0x%x %s, Uptime=%u seconds timestamp=0x%llx\n",
		 log.wwid[0], log.wwid[1],
		 log.log_identifier, log.program_reference_code,
		 log.error_log_type,
		 decode_error_log_type(log.error_log_type),
		 log.power_on_seconds, log.timestamp);
	print_hex_dump(KERN_WARNING, "buf", DUMP_PREFIX_OFFSET, 16, 1, buf,
		       log.buf_size, false);

out:
	kfree(buf);
}

static irqreturn_t imn0_handler(void *private)
{
	struct ocxlpmem *ocxlpmem = private;
	u64 chi = 0;

	(void)ocxlpmem_chi(ocxlpmem, &chi);

	if (chi & GLOBAL_MMIO_CHI_ELA) {
		dev_warn(&ocxlpmem->dev, "Error log is available\n");

		if (ocxlpmem->ev_ctx)
			eventfd_signal(ocxlpmem->ev_ctx, 1);
	}

	if (chi & GLOBAL_MMIO_CHI_CDA) {
		dev_warn(&ocxlpmem->dev, "Controller dump is available\n");

		if (ocxlpmem->ev_ctx)
			eventfd_signal(ocxlpmem->ev_ctx, 1);
	}


	return IRQ_HANDLED;
}

static irqreturn_t imn1_handler(void *private)
{
	struct ocxlpmem *ocxlpmem = private;
	u64 chi = 0;

	(void)ocxlpmem_chi(ocxlpmem, &chi);

	if (chi & (GLOBAL_MMIO_CHI_CFFS | GLOBAL_MMIO_CHI_CHFS)) {
		dev_err(&ocxlpmem->dev,
			"Controller status is fatal, chi=0x%llx, going offline\n", chi);

		if (ocxlpmem->nvdimm_bus) {
			nvdimm_bus_unregister(ocxlpmem->nvdimm_bus);
			ocxlpmem->nvdimm_bus = NULL;
		}

		if (ocxlpmem->ev_ctx)
			eventfd_signal(ocxlpmem->ev_ctx, 1);
	}

	return IRQ_HANDLED;
}


/**
 * ocxlpmem_setup_irq() - Set up the IRQs for the OpenCAPI Persistent Memory device
 * @ocxlpmem: the device metadata
 * Return: 0 on success, negative on failure
 */
static int ocxlpmem_setup_irq(struct ocxlpmem *ocxlpmem)
{
	int rc;
	u64 irq_addr;

	rc = ocxl_afu_irq_alloc(ocxlpmem->ocxl_context, &ocxlpmem->irq_id[0]);
	if (rc)
		return rc;

	rc = ocxl_irq_set_handler(ocxlpmem->ocxl_context, ocxlpmem->irq_id[0],
				  imn0_handler, NULL, ocxlpmem);

	irq_addr = ocxl_afu_irq_get_addr(ocxlpmem->ocxl_context, ocxlpmem->irq_id[0]);
	if (!irq_addr)
		return -EINVAL;

	ocxlpmem->irq_addr[0] = ioremap(irq_addr, PAGE_SIZE);
	if (!ocxlpmem->irq_addr[0])
		return -EINVAL;

	rc = ocxl_global_mmio_write64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_IMA0_OHP,
				      OCXL_LITTLE_ENDIAN,
				      (u64)ocxlpmem->irq_addr[0]);
	if (rc)
		goto out_irq0;

	rc = ocxl_global_mmio_write64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_IMA0_CFP,
				      OCXL_LITTLE_ENDIAN, 0);
	if (rc)
		goto out_irq0;

	rc = ocxl_afu_irq_alloc(ocxlpmem->ocxl_context, &ocxlpmem->irq_id[1]);
	if (rc)
		goto out_irq0;


	rc = ocxl_irq_set_handler(ocxlpmem->ocxl_context, ocxlpmem->irq_id[1],
				  imn1_handler, NULL, ocxlpmem);
	if (rc)
		goto out_irq0;

	irq_addr = ocxl_afu_irq_get_addr(ocxlpmem->ocxl_context, ocxlpmem->irq_id[1]);
	if (!irq_addr) {
		rc = -EFAULT;
		goto out_irq0;
	}

	ocxlpmem->irq_addr[1] = ioremap(irq_addr, PAGE_SIZE);
	if (!ocxlpmem->irq_addr[1]) {
		rc = -EINVAL;
		goto out_irq0;
	}

	rc = ocxl_global_mmio_write64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_IMA1_OHP,
				      OCXL_LITTLE_ENDIAN,
				      (u64)ocxlpmem->irq_addr[1]);
	if (rc)
		goto out_irq1;

	rc = ocxl_global_mmio_write64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_IMA1_CFP,
				      OCXL_LITTLE_ENDIAN, 0);
	if (rc)
		goto out_irq1;

	// Enable doorbells
	rc = ocxl_global_mmio_set64(ocxlpmem->ocxl_afu, GLOBAL_MMIO_CHIE,
				    OCXL_LITTLE_ENDIAN,
				    GLOBAL_MMIO_CHI_ELA | GLOBAL_MMIO_CHI_CDA |
				    GLOBAL_MMIO_CHI_CFFS | GLOBAL_MMIO_CHI_CHFS |
				    GLOBAL_MMIO_CHI_NSCRA);
	if (rc)
		goto out_irq1;

	return 0;

out_irq1:
	iounmap(ocxlpmem->irq_addr[1]);
	ocxlpmem->irq_addr[1] = NULL;

out_irq0:
	iounmap(ocxlpmem->irq_addr[0]);
	ocxlpmem->irq_addr[0] = NULL;

	return rc;
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
	u64 chi;

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

	ocxlpmem->timeouts[ADMIN_COMMAND_ERRLOG] = 2000; // ms
	ocxlpmem->timeouts[ADMIN_COMMAND_HEARTBEAT] = 100; // ms
	ocxlpmem->timeouts[ADMIN_COMMAND_SMART] = 100; // ms
	ocxlpmem->timeouts[ADMIN_COMMAND_CONTROLLER_DUMP] = 1000; // ms
	ocxlpmem->timeouts[ADMIN_COMMAND_CONTROLLER_STATS] = 100; // ms
	ocxlpmem->timeouts[ADMIN_COMMAND_SHUTDOWN] = 1000; // ms
	ocxlpmem->timeouts[ADMIN_COMMAND_FW_UPDATE] = 16000; // ms

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

	if (ocxlpmem_setup_irq(ocxlpmem)) {
		dev_err(&pdev->dev, "Could not set up OCXL IRQs\n");
		goto err;
	}

	if (setup_command_metadata(ocxlpmem)) {
		dev_err(&pdev->dev, "Could not read OCXL command matada\n");
		goto err;
	}

	if (create_cdev(ocxlpmem)) {
		dev_err(&pdev->dev, "Could not create character device\n");
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
	if (ocxlpmem &&
		    (ocxlpmem_chi(ocxlpmem, &chi) == 0) &&
		    (chi & GLOBAL_MMIO_CHI_ELA))
		dump_error_log(ocxlpmem);

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

static int file_init(void)
{
	int rc;

	mutex_init(&minors_idr_lock);
	idr_init(&minors_idr);

	rc = alloc_chrdev_region(&ocxlpmem_dev, 0, NUM_MINORS, "ocxl-pmem");
	if (rc) {
		idr_destroy(&minors_idr);
		pr_err("Unable to allocate OpenCAPI persistent memory major number: %d\n", rc);
		return rc;
	}

	ocxlpmem_class = class_create(THIS_MODULE, "ocxl-pmem");
	if (IS_ERR(ocxlpmem_class)) {
		idr_destroy(&minors_idr);
		pr_err("Unable to create ocxl-pmem class\n");
		unregister_chrdev_region(ocxlpmem_dev, NUM_MINORS);
		return PTR_ERR(ocxlpmem_class);
	}

	return 0;
}

static void file_exit(void)
{
	class_destroy(ocxlpmem_class);
	unregister_chrdev_region(ocxlpmem_dev, NUM_MINORS);
	idr_destroy(&minors_idr);
}

static int __init ocxlpmem_init(void)
{
	int rc;

	rc = file_init();
	if (rc)
		return rc;

	rc = pci_register_driver(&pci_driver);
	if (rc) {
		file_exit();
		return rc;
	}

	return 0;
}

static void ocxlpmem_exit(void)
{
	pci_unregister_driver(&pci_driver);
	file_exit();
}

module_init(ocxlpmem_init);
module_exit(ocxlpmem_exit);

MODULE_DESCRIPTION("OpenCAPI Persistent Memory");
MODULE_LICENSE("GPL");
