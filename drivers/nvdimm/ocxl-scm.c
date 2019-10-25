// SPDX-License-Identifier: GPL-2.0+
// Copyright 2019 IBM Corp.

/*
 * A driver for Storage Class Memory, connected via OpenCAPI
 */

#include <linux/module.h>
#include <misc/ocxl.h>
#include <linux/delay.h>
#include <linux/ndctl.h>
#include <linux/eventfd.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/memory_hotplug.h>
#include "ocxl-scm_internal.h"


static const struct pci_device_id scm_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0625), },
	{ }
};

MODULE_DEVICE_TABLE(pci, scm_pci_tbl);

#define SCM_NUM_MINORS 256 // Total to reserve
#define SCM_USABLE_TIMEOUT 120 // seconds

static dev_t scm_dev;
static struct class *scm_class;
static struct mutex minors_idr_lock;
static struct idr minors_idr;

static const struct attribute_group *scm_pmem_attribute_groups[] = {
	&nvdimm_bus_attribute_group,
	NULL,
};

static const struct attribute_group *scm_pmem_region_attribute_groups[] = {
	&nd_region_attribute_group,
	&nd_device_attribute_group,
	&nd_mapping_attribute_group,
	&nd_numa_attribute_group,
	NULL,
};

/**
 * scm_ndctl_config_write() - Handle a ND_CMD_SET_CONFIG_DATA command from ndctl
 * @scm_data: the SCM metadata
 * @command: the incoming data to write
 * Return: 0 on success, negative on failure
 */
static int scm_ndctl_config_write(struct scm_data *scm_data,
				  struct nd_cmd_set_config_hdr *command)
{
	if (command->in_offset + command->in_length > SCM_LABEL_AREA_SIZE)
		return -EINVAL;

	memcpy_flushcache(scm_data->metadata_addr + command->in_offset, command->in_buf,
			  command->in_length);

	return 0;
}

/**
 * scm_ndctl_config_read() - Handle a ND_CMD_GET_CONFIG_DATA command from ndctl
 * @scm_data: the SCM metadata
 * @command: the read request
 * Return: 0 on success, negative on failure
 */
static int scm_ndctl_config_read(struct scm_data *scm_data,
				 struct nd_cmd_get_config_data_hdr *command)
{
	if (command->in_offset + command->in_length > SCM_LABEL_AREA_SIZE)
		return -EINVAL;

	memcpy(command->out_buf, scm_data->metadata_addr + command->in_offset,
	       command->in_length);

	return 0;
}

/**
 * scm_ndctl_config_size() - Handle a ND_CMD_GET_CONFIG_SIZE command from ndctl
 * @scm_data: the SCM metadata
 * @command: the read request
 * Return: 0 on success, negative on failure
 */
static int scm_ndctl_config_size(struct nd_cmd_get_config_size *command)
{
	command->status = 0;
	command->config_size = SCM_LABEL_AREA_SIZE;
	command->max_xfer = PAGE_SIZE;

	return 0;
}

static int read_smart_attrib(struct scm_data *scm_data, u16 offset,
			     struct scm_smart_attribs *attribs)
{
	u64 val;
	int rc;
	struct scm_smart_attrib *attrib;
	u8 attrib_id;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, offset, OCXL_LITTLE_ENDIAN,
				     &val);
	if (rc)
		return rc;

	attrib_id = (val >> 56) & 0xff;
	switch (attrib_id) {
	case SCM_SMART_ATTR_POWER_ON_HOURS:
		attrib = &attribs->power_on_hours;
		break;

	case SCM_SMART_ATTR_TEMPERATURE:
		attrib = &attribs->temperature;
		break;

	case SCM_SMART_ATTR_LIFE_REMAINING:
		attrib = &attribs->life_remaining;
		break;

	default:
		dev_err(&scm_data->dev, "Unknown smart attrib '%d'", attrib_id);
		return -EFAULT;
	}

	attrib->id = attrib_id;
	attrib->attribute_flags = (val >> 40) & 0xffff;
	attrib->current_val = (val >> 32) & 0xff;
	attrib->threshold_val = (val >> 24) & 0xff;
	attrib->worst_val = (val >> 16) & 0xff;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, offset + 0x08,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	attrib->raw_val = val;

	return 0;
}

static int scm_smart_offset_0x00(struct scm_data *scm_data, u32 *length)
{
	int rc;
	u64 val;

	u16 data_identifier;
	u32 data_length;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	data_identifier = val >> 48;
	data_length = val & 0xFFFFFFFF;

	if (data_identifier != 0x534D) {
		dev_err(&scm_data->dev,
			"Bad data identifier for smart data, expected 'SM', got '%-.*s'\n",
			2, (char *)&data_identifier);
		return -EFAULT;
	}

	*length = data_length;
	return 0;
}

static int scm_smart_update(struct scm_data *scm_data)
{
	u32 length, i;
	int rc;

	mutex_lock(&scm_data->admin_command.lock);

	rc = scm_admin_command_request(scm_data, ADMIN_COMMAND_SMART);
	if (rc)
		goto out;

	rc = scm_admin_command_execute(scm_data);
	if (rc)
		goto out;

	rc = scm_admin_command_complete_timeout(scm_data, ADMIN_COMMAND_SMART);
	if (rc < 0) {
		dev_err(&scm_data->dev, "SMART timeout\n");
		goto out;
	}

	rc = scm_admin_response(scm_data);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS) {
		scm_warn_status(scm_data, "Unexpected status from SMART", rc);
		goto out;
	}

	rc = scm_smart_offset_0x00(scm_data, &length);
	if (rc)
		goto out;

	length /= 0x10; // Length now contains the number of attributes

	for (i = 0; i < length; i++)
		read_smart_attrib(scm_data,
				  scm_data->admin_command.data_offset + 0x08 + i * 0x10,
				  &scm_data->smart);

	rc = scm_admin_response_handled(scm_data);
	if (rc)
		goto out;

	rc = 0;
	goto out;

out:
	mutex_unlock(&scm_data->admin_command.lock);
	return rc;
}

static int scm_ndctl_smart(struct scm_data *scm_data, void *buf,
			   unsigned int buf_len)
{
	int rc;

	if (buf_len != sizeof(scm_data->smart))
		return -EINVAL;

	rc = scm_smart_update(scm_data);
	if (rc)
		return rc;

	memcpy(buf, &scm_data->smart, buf_len);

	return 0;
}


static int scm_ndctl(struct nvdimm_bus_descriptor *nd_desc,
		     struct nvdimm *nvdimm,
		     unsigned int cmd, void *buf, unsigned int buf_len, int *cmd_rc)
{
	struct scm_data *scm_data = container_of(nd_desc, struct scm_data, bus_desc);

	switch (cmd) {
	case ND_CMD_SMART:
		*cmd_rc = scm_ndctl_smart(scm_data, buf, buf_len);
		return 0;

	case ND_CMD_GET_CONFIG_SIZE:
		*cmd_rc = scm_ndctl_config_size(buf);
		return 0;

	case ND_CMD_GET_CONFIG_DATA:
		*cmd_rc = scm_ndctl_config_read(scm_data, buf);
		return 0;

	case ND_CMD_SET_CONFIG_DATA:
		*cmd_rc = scm_ndctl_config_write(scm_data, buf);
		return 0;

	default:
		return -ENOTTY;
	}
}

static ssize_t serial_show(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	struct scm_data *scm_data = nvdimm_provider_data(nvdimm);
	const struct ocxl_fn_config *config = ocxl_function_config(scm_data->ocxl_fn);

	return sprintf(buf, "0x%llx\n", config->serial);
}
static DEVICE_ATTR_RO(serial);

static struct attribute *scm_dimm_attributes[] = {
	&dev_attr_serial.attr,
	NULL,
};

static umode_t scm_dimm_attr_visible(struct kobject *kobj,
				     struct attribute *a, int n)
{
	return a->mode;
}

static const struct attribute_group scm_dimm_attribute_group = {
	.name = "scm",
	.attrs = scm_dimm_attributes,
	.is_visible = scm_dimm_attr_visible,
};

static const struct attribute_group *scm_dimm_attribute_groups[] = {
	&nvdimm_attribute_group,
	&nd_device_attribute_group,
	&scm_dimm_attribute_group,
	NULL,
};

/**
 * scm_reserve_metadata() - Reserve space for nvdimm metadata
 * @scm_data: The SCM device data
 * @lpc_mem: The resource representing the LPC memory of the SCM device
 */
static int scm_reserve_metadata(struct scm_data *scm_data,
				struct resource *lpc_mem)
{
	scm_data->metadata_addr = devm_memremap(&scm_data->dev, lpc_mem->start,
						SCM_LABEL_AREA_SIZE, MEMREMAP_WB);
	if (IS_ERR(scm_data->metadata_addr))
		return PTR_ERR(scm_data->metadata_addr);

	return 0;
}

/**
 * scm_overwrite() - Overwrite all data on the card
 * @scm_data: The SCM device data
 * Return: 0 on success
 */
int scm_overwrite(struct scm_data *scm_data)
{
	int rc;

	mutex_lock(&scm_data->ns_command.lock);

	rc = scm_ns_command_request(scm_data, NS_COMMAND_SECURE_ERASE);
	if (rc)
		goto out;

	rc = scm_ns_command_execute(scm_data);
	if (rc)
		goto out;

	scm_data->overwrite_state = SCM_OVERWRITE_BUSY;

	return 0;

out:
	mutex_unlock(&scm_data->ns_command.lock);
	return rc;
}

/**
 * scm_secop_overwrite() - Overwrite all data on the card
 * @nvdimm: The nvdimm representation of the SCM device to start the overwrite on
 * @key_data: Unused (no security key implementation)
 * Return: 0 on success
 */
static int scm_secop_overwrite(struct nvdimm *nvdimm,
			       const struct nvdimm_key_data *key_data)
{
	struct scm_data *scm_data = nvdimm_provider_data(nvdimm);

	return scm_overwrite(scm_data);
}

/**
 * scm_secop_query_overwrite() - Get the current overwrite state
 * @nvdimm: The nvdimm representation of the SCM device to start the overwrite on
 * Return: 0 if successful or idle, -EBUSY if busy, -EFAULT if failed
 */
static int scm_secop_query_overwrite(struct nvdimm *nvdimm)
{
	struct scm_data *scm_data = nvdimm_provider_data(nvdimm);

	if (scm_data->overwrite_state == SCM_OVERWRITE_BUSY)
		return -EBUSY;

	if (scm_data->overwrite_state == SCM_OVERWRITE_FAILED)
		return -EFAULT;

	return 0;
}

/**
 * scm_secop_get_flags() - return the security flags for the SCM device
 */
static unsigned long scm_secop_get_flags(struct nvdimm *nvdimm,
		enum nvdimm_passphrase_type ptype)
{
	struct scm_data *scm_data = nvdimm_provider_data(nvdimm);

	if (scm_data->overwrite_state == SCM_OVERWRITE_BUSY)
		return BIT(NVDIMM_SECURITY_OVERWRITE);

	return BIT(NVDIMM_SECURITY_DISABLED);
}

static const struct nvdimm_security_ops sec_ops  = {
	.get_flags = scm_secop_get_flags,
	.overwrite = scm_secop_overwrite,
	.query_overwrite = scm_secop_query_overwrite,
};

/**
 * scm_register_lpc_mem() - Discover persistent memory on a device and register it with the NVDIMM subsystem
 * @scm_data: The SCM device data
 * Return: 0 on success
 */
static int scm_register_lpc_mem(struct scm_data *scm_data)
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
	rc = ocxl_afu_map_lpc_mem(scm_data->ocxl_afu);
	if (rc < 0)
		return rc;

	lpc_mem = ocxl_afu_lpc_mem(scm_data->ocxl_afu);
	if (lpc_mem == NULL)
		return -EINVAL;

	config = ocxl_afu_config(scm_data->ocxl_afu);
	fn_config = ocxl_function_config(scm_data->ocxl_fn);

	rc = scm_reserve_metadata(scm_data, lpc_mem);
	if (rc)
		return rc;

	scm_data->bus_desc.attr_groups = scm_pmem_attribute_groups;
	scm_data->bus_desc.provider_name = "scm";
	scm_data->bus_desc.ndctl = scm_ndctl;
	scm_data->bus_desc.module = THIS_MODULE;

	scm_data->nvdimm_bus = nvdimm_bus_register(&scm_data->dev,
			       &scm_data->bus_desc);
	if (!scm_data->nvdimm_bus)
		return -EINVAL;

	scm_data->scm_res.start = (u64)lpc_mem->start + SCM_LABEL_AREA_SIZE;
	scm_data->scm_res.end = (u64)lpc_mem->start + config->lpc_mem_size - 1;
	scm_data->scm_res.name = "SCM persistent memory";

	set_bit(ND_CMD_GET_CONFIG_SIZE, &nvdimm_cmd_mask);
	set_bit(ND_CMD_GET_CONFIG_DATA, &nvdimm_cmd_mask);
	set_bit(ND_CMD_SET_CONFIG_DATA, &nvdimm_cmd_mask);
	set_bit(ND_CMD_SMART, &nvdimm_cmd_mask);

	set_bit(NDD_ALIASING, &nvdimm_flags);

	snprintf(serial, sizeof(serial), "%llx", fn_config->serial);
	nd_mapping_desc.nvdimm = __nvdimm_create(scm_data->nvdimm_bus, scm_data,
				 scm_dimm_attribute_groups,
				 nvdimm_flags, nvdimm_cmd_mask,
				 0, NULL, serial, &sec_ops);
	if (!nd_mapping_desc.nvdimm)
		return -ENOMEM;

	if (nvdimm_bus_check_dimm_count(scm_data->nvdimm_bus, 1))
		return -EINVAL;

	nd_mapping_desc.start = scm_data->scm_res.start;
	nd_mapping_desc.size = resource_size(&scm_data->scm_res);
	nd_mapping_desc.position = 0;

	scm_data->nd_set.cookie1 = fn_config->serial + 1; // allow for empty serial
	scm_data->nd_set.cookie2 = fn_config->serial + 1;

	target_node = of_node_to_nid(scm_data->pdev->dev.of_node);

	memset(&region_desc, 0, sizeof(region_desc));
	region_desc.res = &scm_data->scm_res;
	region_desc.attr_groups = scm_pmem_region_attribute_groups;
	region_desc.numa_node = NUMA_NO_NODE;
	region_desc.target_node = target_node;
	region_desc.num_mappings = 1;
	region_desc.mapping = &nd_mapping_desc;
	region_desc.nd_set = &scm_data->nd_set;

	set_bit(ND_REGION_PAGEMAP, &region_desc.flags);
	/*
	 * NB: libnvdimm copies the data from ndr_desc into it's own
	 * structures so passing a stack pointer is fine.
	 */
	scm_data->nd_region = nvdimm_pmem_region_create(scm_data->nvdimm_bus,
			      &region_desc);
	if (!scm_data->nd_region)
		return -EINVAL;

	dev_info(&scm_data->dev,
		 "Onlining %lluMB of persistent memory\n",
		 nd_mapping_desc.size / SZ_1M);

	return 0;
}

/**
 * scm_is_memory_available() - Does the controller have memory available?
 * @scm_data: a pointer to the SCM device data
 * Return: true if the controller has memory available
 */
static bool scm_is_memory_available(const struct scm_data *scm_data)
{
	u64 val = 0;
	int rc = scm_chi(scm_data, &val);

	WARN_ON(rc < 0);

	return (val & GLOBAL_MMIO_CHI_MA) != 0;
}

/**
 * scm_extract_command_metadata() - Extract command data from MMIO & save it for further use
 * @scm_data: a pointer to the SCM device data
 * @offset: The base address of the command data structures (address of CREQO)
 * @command_metadata: A pointer to the command metadata to populate
 * Return: 0 on success, negative on failure
 */
static int scm_extract_command_metadata(struct scm_data *scm_data, u32 offset,
					struct command_metadata *command_metadata)
{
	int rc;
	u64 tmp;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, offset, OCXL_LITTLE_ENDIAN,
				     &tmp);
	if (rc)
		return rc;

	command_metadata->request_offset = tmp >> 32;
	command_metadata->response_offset = tmp & 0xFFFFFFFF;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, offset + 8, OCXL_LITTLE_ENDIAN,
				     &tmp);
	if (rc)
		return rc;

	command_metadata->data_offset = tmp >> 32;
	command_metadata->data_size = tmp & 0xFFFFFFFF;

	command_metadata->id = 0;

	return 0;
}

/**
 * scm_setup_command_metadata() - Set up the command metadata
 * @scm_data: a pointer to the SCM device data
 */
static int scm_setup_command_metadata(struct scm_data *scm_data)
{
	int rc;

	rc = scm_extract_command_metadata(scm_data, GLOBAL_MMIO_ACMA_CREQO,
					  &scm_data->admin_command);
	if (rc)
		return rc;

	rc = scm_extract_command_metadata(scm_data, GLOBAL_MMIO_NSCMA_CREQO,
					  &scm_data->ns_command);
	if (rc)
		return rc;

	return 0;
}

/**
 * scm_heartbeat() - Issue a heartbeat command to the controller
 * @scm_data: a pointer to the SCM device data
 * Return: 0 if the controller responded correctly, negative on error
 */
static int scm_heartbeat(struct scm_data *scm_data)
{
	int rc;

	mutex_lock(&scm_data->admin_command.lock);

	rc = scm_admin_command_request(scm_data, ADMIN_COMMAND_HEARTBEAT);
	if (rc)
		goto out;

	rc = scm_admin_command_execute(scm_data);
	if (rc)
		goto out;

	rc = scm_admin_command_complete_timeout(scm_data, ADMIN_COMMAND_HEARTBEAT);
	if (rc < 0) {
		dev_err(&scm_data->dev, "Heartbeat timeout\n");
		goto out;
	}

	rc = scm_admin_response(scm_data);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS)
		scm_warn_status(scm_data, "Unexpected status from heartbeat", rc);

	rc = scm_admin_response_handled(scm_data);

	goto out;

out:
	mutex_unlock(&scm_data->admin_command.lock);
	return rc;
}

/**
 * scm_is_usable() - Is a controller usable?
 * @scm_data: a pointer to the SCM device data
 * Return: true if the controller is usable
 */
static bool scm_is_usable(const struct scm_data *scm_data)
{
	if (!scm_controller_is_ready(scm_data)) {
		dev_err(&scm_data->dev, "SCM controller is not ready.\n");
		return false;
	}

	if (!scm_is_memory_available(scm_data)) {
		dev_err(&scm_data->dev,
			"SCM controller does not have memory available.\n");
		return false;
	}

	return true;
}

/**
 * allocate_scm_minor() - Allocate a minor number to use for an SCM device
 * @scm_data: The SCM device to associate the minor with
 * Return: the allocated minor number
 */
static int allocate_scm_minor(struct scm_data *scm_data)
{
	int minor;

	mutex_lock(&minors_idr_lock);
	minor = idr_alloc(&minors_idr, scm_data, 0, SCM_NUM_MINORS, GFP_KERNEL);
	mutex_unlock(&minors_idr_lock);
	return minor;
}

static void free_scm_minor(struct scm_data *scm_data)
{
	mutex_lock(&minors_idr_lock);
	idr_remove(&minors_idr, MINOR(scm_data->dev.devt));
	mutex_unlock(&minors_idr_lock);
}

/**
 * free_scm() - Free all members of an SCM struct
 * @scm_data: the SCM metadata to clear
 */
static void free_scm(struct scm_data *scm_data)
{
	// Disable doorbells
	(void)ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_CHIEC,
				     OCXL_LITTLE_ENDIAN,
				     GLOBAL_MMIO_CHI_ALL);

	free_scm_minor(scm_data);

	if (scm_data->irq_addr[1])
		iounmap(scm_data->irq_addr[1]);

	if (scm_data->irq_addr[0])
		iounmap(scm_data->irq_addr[0]);

	if (scm_data->cdev.owner)
		cdev_del(&scm_data->cdev);

	if (scm_data->metadata_addr)
		devm_memunmap(&scm_data->dev, scm_data->metadata_addr);

	if (scm_data->ocxl_context)
		ocxl_context_free(scm_data->ocxl_context);

	if (scm_data->ocxl_afu)
		ocxl_afu_put(scm_data->ocxl_afu);

	if (scm_data->ocxl_fn)
		ocxl_function_close(scm_data->ocxl_fn);

	kfree(scm_data);
}

/**
 * free_scm_dev - Free an SCM device
 * @dev: The device struct
 */
static void free_scm_dev(struct device *dev)
{
	struct scm_data *scm_data = container_of(dev, struct scm_data, dev);

	free_scm(scm_data);
}

/**
 * scm_register - Register an SCM device with the kernel
 * @scm_data: the SCM metadata
 * Return: 0 on success, negative on failure
 */
static int scm_register(struct scm_data *scm_data)
{
	int rc;
	int minor = allocate_scm_minor(scm_data);

	if (minor < 0)
		return minor;

	scm_data->dev.release = free_scm_dev;
	rc = dev_set_name(&scm_data->dev, "scm%d", minor);
	if (rc < 0)
		return rc;

	scm_data->dev.devt = MKDEV(MAJOR(scm_dev), minor);
	scm_data->dev.class = scm_class;
	scm_data->dev.parent = &scm_data->pdev->dev;

	rc = device_register(&scm_data->dev);
	return rc;
}

static void scm_put(struct scm_data *scm_data)
{
	put_device(&scm_data->dev);
}

struct scm_data *scm_get(struct scm_data *scm_data)
{
	return (get_device(&scm_data->dev) == NULL) ? NULL : scm_data;
}

static struct scm_data *find_and_get_scm(dev_t devno)
{
	struct scm_data *scm_data;
	int minor = MINOR(devno);
	/*
	 * We don't declare an RCU critical section here, as our AFU
	 * is protected by a reference counter on the device. By the time the
	 * minor number of a device is removed from the idr, the ref count of
	 * the device is already at 0, so no user API will access that AFU and
	 * this function can't return it.
	 */
	scm_data = idr_find(&minors_idr, minor);
	if (scm_data)
		scm_get(scm_data);
	return scm_data;
}

static int scm_file_open(struct inode *inode, struct file *file)
{
	struct scm_data *scm_data;

	scm_data = find_and_get_scm(inode->i_rdev);
	if (!scm_data)
		return -ENODEV;

	file->private_data = scm_data;
	return 0;
}

static int scm_file_release(struct inode *inode, struct file *file)
{
	struct scm_data *scm_data = file->private_data;

	if (scm_data->ev_ctx) {
		eventfd_ctx_put(scm_data->ev_ctx);
		scm_data->ev_ctx = NULL;
	}

	scm_put(scm_data);
	return 0;
}

static int scm_ioctl_buffer_info(struct scm_data *scm_data,
				 struct scm_ioctl_buffer_info __user *uarg)
{
	struct scm_ioctl_buffer_info args;

	args.admin_command_buffer_size = scm_data->admin_command.data_size;
	args.near_storage_buffer_size = scm_data->ns_command.data_size;

	if (copy_to_user(uarg, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static int scm_error_log_offset_0x00(struct scm_data *scm_data, u16 *length)
{
	int rc;
	u64 val;

	u16 data_identifier;
	u32 data_length;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	data_identifier = val >> 48;
	data_length = val & 0xFFFF;

	if (data_identifier != 0x454C) {
		dev_err(&scm_data->dev,
			"Bad data identifier for error log data, expected 'EL', got '%2s' (%#x), data_length=%u\n",
			(char *)&data_identifier,
			(unsigned int)data_identifier, data_length);
		return -EFAULT;
	}

	*length = data_length;
	return 0;
}

static int scm_error_log_offset_0x08(struct scm_data *scm_data,
				     u32 *log_identifier, u32 *program_ref_code)
{
	int rc;
	u64 val;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	*log_identifier = val >> 32;
	*program_ref_code = val & 0xFFFFFFFF;

	return 0;
}

static int scm_read_error_log(struct scm_data *scm_data,
			      struct scm_ioctl_error_log *log, bool buf_is_user)
{
	u64 val;
	u16 user_buf_length;
	u16 buf_length;
	u16 i;
	int rc;

	if (log->buf_size % 8)
		return -EINVAL;

	rc = scm_chi(scm_data, &val);
	if (rc)
		goto out;

	if (!(val & GLOBAL_MMIO_CHI_ELA))
		return -EAGAIN;

	user_buf_length = log->buf_size;

	mutex_lock(&scm_data->admin_command.lock);

	rc = scm_admin_command_request(scm_data, ADMIN_COMMAND_ERRLOG);
	if (rc)
		goto out;

	rc = scm_admin_command_execute(scm_data);
	if (rc)
		goto out;

	rc = scm_admin_command_complete_timeout(scm_data, ADMIN_COMMAND_ERRLOG);
	if (rc < 0) {
		dev_warn(&scm_data->dev, "Read error log timed out\n");
		goto out;
	}

	rc = scm_admin_response(scm_data);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS) {
		scm_warn_status(scm_data, "Unexpected status from retrieve error log", rc);
		goto out;
	}


	rc = scm_error_log_offset_0x00(scm_data, &log->buf_size);
	if (rc)
		goto out;
	// log->buf_size now contains the scm buffer size, not the user size

	rc = scm_error_log_offset_0x08(scm_data, &log->log_identifier,
				       &log->program_reference_code);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x10,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		goto out;

	log->error_log_type = val >> 56;
	log->action_flags = (log->error_log_type == SCM_ERROR_LOG_TYPE_GENERAL) ?
			    (val >> 32) & 0xFFFFFF : 0;
	log->power_on_seconds = val & 0xFFFFFFFF;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x18,
				     OCXL_LITTLE_ENDIAN, &log->timestamp);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x20,
				     OCXL_HOST_ENDIAN, &log->wwid[0]);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x28,
				     OCXL_HOST_ENDIAN, &log->wwid[1]);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x30,
				     OCXL_HOST_ENDIAN, (u64 *)log->fw_revision);
	if (rc)
		goto out;
	log->fw_revision[8] = '\0';

	buf_length = (user_buf_length < log->buf_size) ?
		     user_buf_length : log->buf_size;
	for (i = 0; i < buf_length + 0x48; i += 8) {
		u64 val;

		rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
					     scm_data->admin_command.data_offset + i,
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

	rc = scm_admin_response_handled(scm_data);
	if (rc)
		goto out;

out:
	mutex_unlock(&scm_data->admin_command.lock);
	return rc;

}

static int scm_ioctl_error_log(struct scm_data *scm_data,
			       struct scm_ioctl_error_log __user *uarg)
{
	struct scm_ioctl_error_log args;
	int rc;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	rc = scm_read_error_log(scm_data, &args, true);
	if (rc)
		return rc;

	if (copy_to_user(uarg, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static int scm_ioctl_controller_dump_data(struct scm_data *scm_data,
	struct scm_ioctl_controller_dump_data __user *uarg)
{
	struct scm_ioctl_controller_dump_data args;
	u16 i;
	u64 val;
	int rc;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	if (args.buf_size % 8)
		return -EINVAL;

	if (args.buf_size > scm_data->admin_command.data_size)
		return -EINVAL;

	mutex_lock(&scm_data->admin_command.lock);

	rc = scm_admin_command_request(scm_data, ADMIN_COMMAND_CONTROLLER_DUMP);
	if (rc)
		goto out;

	val = ((u64)args.offset) << 32;
	val |= args.buf_size;
	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
				      scm_data->admin_command.request_offset + 0x08,
				      OCXL_LITTLE_ENDIAN, val);
	if (rc)
		goto out;

	rc = scm_admin_command_execute(scm_data);
	if (rc)
		goto out;

	rc = scm_admin_command_complete_timeout(scm_data,
						ADMIN_COMMAND_CONTROLLER_DUMP);
	if (rc < 0) {
		dev_warn(&scm_data->dev, "Controller dump timed out\n");
		goto out;
	}

	rc = scm_admin_response(scm_data);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS) {
		scm_warn_status(scm_data,
				"Unexpected status from retrieve error log",
				rc);
		goto out;
	}

	for (i = 0; i < args.buf_size; i += 8) {
		u64 val;

		rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
					     scm_data->admin_command.data_offset + i,
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

	rc = scm_admin_response_handled(scm_data);
	if (rc)
		goto out;

out:
	mutex_unlock(&scm_data->admin_command.lock);
	return rc;
}

int scm_request_controller_dump(struct scm_data *scm_data)
{
	int rc;
	u64 busy = 1;

	rc = ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_CHIC,
				    OCXL_LITTLE_ENDIAN,
				    GLOBAL_MMIO_CHI_CDA);


	rc = ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_HCI,
				    OCXL_LITTLE_ENDIAN,
				    GLOBAL_MMIO_HCI_CONTROLLER_DUMP);
	if (rc)
		return rc;

	while (busy) {
		rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
					     GLOBAL_MMIO_HCI,
					     OCXL_LITTLE_ENDIAN, &busy);
		if (rc)
			return rc;

		busy &= GLOBAL_MMIO_HCI_CONTROLLER_DUMP;
		cond_resched();
	}

	return 0;
}

static int scm_ioctl_controller_dump_complete(struct scm_data *scm_data)
{
	int rc;

	rc = ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_HCI,
				    OCXL_LITTLE_ENDIAN,
				    GLOBAL_MMIO_HCI_CONTROLLER_DUMP_COLLECTED);

	if (rc)
		return -EFAULT;

	return 0;
}

static int scm_controller_stats_offset_0x00(struct scm_data *scm_data,
	u32 *length)
{
	int rc;
	u64 val;

	u16 data_identifier;
	u32 data_length;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	data_identifier = val >> 48;
	data_length = val & 0xFFFFFFFF;

	if (data_identifier != 0x4353) {
		dev_err(&scm_data->dev,
			"Bad data identifier for controller stats, expected 'CS', got '%-.*s'\n",
			2, (char *)&data_identifier);
		return -EFAULT;
	}

	*length = data_length;
	return 0;
}

static int scm_ioctl_controller_stats(struct scm_data *scm_data,
				      struct scm_ioctl_controller_stats __user *uarg)
{
	struct scm_ioctl_controller_stats args;
	u32 length;
	int rc;
	u64 val;

	memset(&args, '\0', sizeof(args));

	mutex_lock(&scm_data->admin_command.lock);

	rc = scm_admin_command_request(scm_data, ADMIN_COMMAND_CONTROLLER_STATS);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
				      scm_data->admin_command.request_offset + 0x08,
				      OCXL_LITTLE_ENDIAN, 0);
	if (rc)
		goto out;

	rc = scm_admin_command_execute(scm_data);
	if (rc)
		goto out;


	rc = scm_admin_command_complete_timeout(scm_data,
						ADMIN_COMMAND_CONTROLLER_STATS);
	if (rc < 0) {
		dev_warn(&scm_data->dev, "Controller stats timed out\n");
		goto out;
	}

	rc = scm_admin_response(scm_data);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS) {
		scm_warn_status(scm_data,
				"Unexpected status from controller stats", rc);
		goto out;
	}

	rc = scm_controller_stats_offset_0x00(scm_data, &length);
	if (rc)
		goto out;

	if (length != 0x140)
		scm_warn_status(scm_data,
				"Unexpected length for controller stats data, expected 0x140, got 0x%x",
				length);

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x08,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		goto out;

	args.reset_count = val >> 32;
	args.reset_uptime = val & 0xFFFFFFFF;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x10,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		goto out;

	args.power_on_uptime = val >> 32;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x08,
				     OCXL_LITTLE_ENDIAN, &args.host_load_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x10,
				     OCXL_LITTLE_ENDIAN, &args.host_store_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x18,
				     OCXL_LITTLE_ENDIAN, &args.media_read_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x20,
				     OCXL_LITTLE_ENDIAN, &args.media_write_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x28,
				     OCXL_LITTLE_ENDIAN, &args.cache_hit_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x30,
				     OCXL_LITTLE_ENDIAN, &args.cache_miss_count);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x38,
				     OCXL_LITTLE_ENDIAN, &args.media_read_latency);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x40,
				     OCXL_LITTLE_ENDIAN, &args.media_write_latency);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x48,
				     OCXL_LITTLE_ENDIAN, &args.cache_read_latency);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
				     scm_data->admin_command.data_offset + 0x08 + 0x40 + 0x50,
				     OCXL_LITTLE_ENDIAN, &args.cache_write_latency);
	if (rc)
		goto out;

	if (copy_to_user(uarg, &args, sizeof(args))) {
		rc = -EFAULT;
		goto out;
	}

	rc = scm_admin_response_handled(scm_data);
	if (rc)
		goto out;

	rc = 0;
	goto out;

out:
	mutex_unlock(&scm_data->admin_command.lock);
	return rc;
}

static int scm_ioctl_eventfd(struct scm_data *scm_data,
			     struct scm_ioctl_eventfd __user *uarg)
{
	struct scm_ioctl_eventfd args;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	if (scm_data->ev_ctx)
		return -EFAULT;

	scm_data->ev_ctx = eventfd_ctx_fdget(args.eventfd);
	if (!scm_data->ev_ctx)
		return -EFAULT;

	return 0;
}

static int scm_ioctl_event_check(struct scm_data *scm_data, u64 __user *uarg)
{
	u64 val = 0;
	int rc;
	u64 chi = 0;

	rc = scm_chi(scm_data, &chi);
	if (rc < 0)
		return -EFAULT;

	if (chi & GLOBAL_MMIO_CHI_ELA)
		val |= SCM_IOCTL_EVENT_ERROR_LOG_AVAILABLE;

	if (chi & GLOBAL_MMIO_CHI_CDA)
		val |= SCM_IOCTL_EVENT_CONTROLLER_DUMP_AVAILABLE;

	if (chi & GLOBAL_MMIO_CHI_CFFS)
		val |= SCM_IOCTL_EVENT_FIRMWARE_FATAL;

	if (chi & GLOBAL_MMIO_CHI_CHFS)
		val |= SCM_IOCTL_EVENT_HARDWARE_FATAL;

	rc = copy_to_user((u64 __user *) uarg, &val, sizeof(val));

	return rc;
}

/**
 * scm_req_controller_health_perf() - Request controller health & performance data
 * @scm_data: the SCM metadata
 * Return: 0 on success, negative on failure
 */
int scm_req_controller_health_perf(struct scm_data *scm_data)
{
	return ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_HCI,
				      OCXL_LITTLE_ENDIAN,
				      GLOBAL_MMIO_HCI_REQ_HEALTH_PERF);
}

#ifdef CONFIG_OCXL_SCM_DEBUG
/**
 * scm_enable_fwdebug() - Enable FW debug on the controller
 * @scm_data: a pointer to the SCM device data
 * Return: 0 on success, negative on failure
 */
static int scm_enable_fwdebug(const struct scm_data *scm_data)
{
	return ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_HCI,
				      OCXL_LITTLE_ENDIAN,
				      GLOBAL_MMIO_HCI_FW_DEBUG);
}

/**
 * scm_disable_fwdebug() - Disable FW debug on the controller
 * @scm_data: a pointer to the SCM device data
 * Return: 0 on success, negative on failure
 */
static int scm_disable_fwdebug(const struct scm_data *scm_data)
{
	return ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_HCIC,
				      OCXL_LITTLE_ENDIAN,
				      GLOBAL_MMIO_HCI_FW_DEBUG);
}

static int scm_ioctl_fwdebug(struct scm_data *scm_data,
			     struct scm_ioctl_fwdebug __user *uarg)
{
	struct scm_ioctl_fwdebug args;
	u64 val;
	int i;
	int rc;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	// Buffer size must be a multiple of 8
	if ((args.buf_size & 0x07))
		return -EINVAL;

	if (args.buf_size > scm_data->admin_command.data_size)
		return -EINVAL;

	mutex_lock(&scm_data->admin_command.lock);

	rc = scm_enable_fwdebug(scm_data);
	if (rc)
		goto out;

	rc = scm_admin_command_request(scm_data, ADMIN_COMMAND_FW_DEBUG);
	if (rc)
		goto out;

	// Write DebugAction & FunctionCode
	val = ((u64)args.debug_action << 56) | ((u64)args.function_code << 40);

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
				      scm_data->admin_command.request_offset + 0x08,
				      OCXL_LITTLE_ENDIAN, val);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
				      scm_data->admin_command.request_offset + 0x10,
				      OCXL_LITTLE_ENDIAN, args.debug_parameter_1);
	if (rc)
		goto out;

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
				      scm_data->admin_command.request_offset + 0x18,
				      OCXL_LITTLE_ENDIAN, args.debug_parameter_2);
	if (rc)
		goto out;

	for (i = 0x20; i < 0x38; i += 0x08)
		rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
					      scm_data->admin_command.request_offset + i,
					      OCXL_LITTLE_ENDIAN, 0);
	if (rc)
		goto out;


	// Populate admin command buffer
	if (args.buf_size) {
		for (i = 0; i < args.buf_size; i += sizeof(u64)) {
			u64 val;

			if (copy_from_user(&val, &args.buf[i], sizeof(u64)))
				return -EFAULT;

			rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
						      scm_data->admin_command.data_offset + i,
						      OCXL_HOST_ENDIAN, val);
			if (rc)
				goto out;
		}
	}

	rc = scm_admin_command_execute(scm_data);
	if (rc)
		goto out;

	rc = scm_admin_command_complete_timeout(scm_data,
						scm_data->timeouts[ADMIN_COMMAND_FW_DEBUG]);
	if (rc < 0)
		goto out;

	rc = scm_admin_response(scm_data);
	if (rc < 0)
		goto out;
	if (rc != STATUS_SUCCESS) {
		scm_warn_status(scm_data, "Unexpected status from FW Debug", rc);
		goto out;
	}

	if (args.buf_size) {
		for (i = 0; i < args.buf_size; i += sizeof(u64)) {
			u64 val;

			rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
						     scm_data->admin_command.data_offset + i,
						     OCXL_HOST_ENDIAN, &val);
			if (rc)
				goto out;

			if (copy_to_user(&args.buf[i], &val, sizeof(u64))) {
				rc = -EFAULT;
				goto out;
			}
		}
	}

	rc = scm_admin_response_handled(scm_data);
	if (rc)
		goto out;

	rc = scm_disable_fwdebug(scm_data);
	if (rc)
		goto out;

out:
	mutex_unlock(&scm_data->admin_command.lock);
	return rc;
}

static int scm_ioctl_shutdown(struct scm_data *scm_data)
{
	int rc;

	mutex_lock(&scm_data->admin_command.lock);

	rc = scm_admin_command_request(scm_data, ADMIN_COMMAND_SHUTDOWN);
	if (rc)
		goto out;

	rc = scm_admin_command_execute(scm_data);
	if (rc)
		goto out;

	rc = scm_admin_command_complete_timeout(scm_data, ADMIN_COMMAND_SHUTDOWN);
	if (rc < 0) {
		dev_warn(&scm_data->dev, "Shutdown timed out\n");
		goto out;
	}

	rc = 0;
	goto out;

out:
	mutex_unlock(&scm_data->admin_command.lock);
	return rc;
}

static int scm_ioctl_mmio_write(struct scm_data *scm_data,
				struct scm_ioctl_mmio __user *uarg)
{
	struct scm_ioctl_mmio args;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	return ocxl_global_mmio_write64(scm_data->ocxl_afu, args.address,
					OCXL_LITTLE_ENDIAN, args.val);
}

static int scm_ioctl_mmio_read(struct scm_data *scm_data,
			       struct scm_ioctl_mmio __user *uarg)
{
	struct scm_ioctl_mmio args;
	int rc;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, args.address,
				     OCXL_LITTLE_ENDIAN, &args.val);
	if (rc)
		return rc;

	if (copy_to_user(uarg, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}
#else
static int scm_ioctl_fwdebug(struct scm_data *scm_data,
			     struct scm_ioctl_fwdebug __user *uarg)
{
	return -EPERM;
}

static int scm_ioctl_shutdown(struct scm_data *scm_data)
{
	return -EPERM;
}

static int scm_ioctl_mmio_write(struct scm_data *scm_data,
				struct scm_ioctl_mmio __user *uarg)
{
	return -EPERM;
}

static int scm_ioctl_mmio_read(struct scm_data *scm_data,
			       struct scm_ioctl_mmio __user *uarg)
{
	return -EPERM;
}
#endif

static long scm_file_ioctl(struct file *file, unsigned int cmd,
			   unsigned long args)
{
	struct scm_data *scm_data = file->private_data;
	int rc = -EINVAL;

	switch (cmd) {
	case SCM_IOCTL_BUFFER_INFO:
		rc = scm_ioctl_buffer_info(scm_data,
					   (struct scm_ioctl_buffer_info __user *)args);
		break;

	case SCM_IOCTL_ERROR_LOG:
		rc = scm_ioctl_error_log(scm_data,
					 (struct scm_ioctl_error_log __user *)args);
		break;

	case SCM_IOCTL_CONTROLLER_DUMP:
		rc = scm_request_controller_dump(scm_data);
		break;

	case SCM_IOCTL_CONTROLLER_DUMP_DATA:
		rc = scm_ioctl_controller_dump_data(scm_data,
						    (struct scm_ioctl_controller_dump_data __user *)args);
		break;

	case SCM_IOCTL_CONTROLLER_DUMP_COMPLETE:
		rc = scm_ioctl_controller_dump_complete(scm_data);
		break;

	case SCM_IOCTL_CONTROLLER_STATS:
		rc = scm_ioctl_controller_stats(scm_data,
						(struct scm_ioctl_controller_stats __user *)args);
		break;

	case SCM_IOCTL_EVENTFD:
		rc = scm_ioctl_eventfd(scm_data,
				       (struct scm_ioctl_eventfd __user *)args);
		break;

	case SCM_IOCTL_EVENT_CHECK:
		rc = scm_ioctl_event_check(scm_data, (u64 __user *)args);
		break;

	case SCM_IOCTL_REQUEST_HEALTH:
		rc = scm_req_controller_health_perf(scm_data);
		break;

	case SCM_IOCTL_FWDEBUG:
		rc = scm_ioctl_fwdebug(scm_data,
				       (struct scm_ioctl_fwdebug __user *)args);
		break;

	case SCM_IOCTL_SHUTDOWN:
		rc = scm_ioctl_shutdown(scm_data);
		break;

	case SCM_IOCTL_MMIO_WRITE:
		rc = scm_ioctl_mmio_write(scm_data,
					  (struct scm_ioctl_mmio __user *)args);
		break;

	case SCM_IOCTL_MMIO_READ:
		rc = scm_ioctl_mmio_read(scm_data,
					 (struct scm_ioctl_mmio __user *)args);
		break;

	}

	return rc;
}

static const struct file_operations scm_fops = {
	.owner		= THIS_MODULE,
	.open	   = scm_file_open,
	.release	= scm_file_release,
	.unlocked_ioctl = scm_file_ioctl,
	.compat_ioctl   = scm_file_ioctl,
};

/**
 * scm_create_cdev() - Create the chardev in /dev for this scm device
 * @scm_data: the SCM metadata
 * Return: 0 on success, negative on failure
 */
static int scm_create_cdev(struct scm_data *scm_data)
{
	int rc;

	cdev_init(&scm_data->cdev, &scm_fops);
	rc = cdev_add(&scm_data->cdev, scm_data->dev.devt, 1);
	if (rc) {
		dev_err(&scm_data->dev, "Unable to add afu char device: %d\n", rc);
		return rc;
	}
	return 0;
}

/**
 * scm_remove() - Free an OpenCAPI Storage Class Memory device
 * @pdev: the PCI device information struct
 */
static void scm_remove(struct pci_dev *pdev)
{
	if (PCI_FUNC(pdev->devfn) == 0) {
		struct scm_function_0 *scm_func_0 = pci_get_drvdata(pdev);

		if (scm_func_0) {
			ocxl_function_close(scm_func_0->ocxl_fn);
			scm_func_0->ocxl_fn = NULL;
		}
	} else {
		struct scm_data *scm_data = pci_get_drvdata(pdev);

		if (scm_data) {
			if (scm_data->nvdimm_bus)
				nvdimm_bus_unregister(scm_data->nvdimm_bus);

			device_unregister(&scm_data->dev);
		}
	}
}

/**
 * scm_setup_device_metadata() - Retrieve config information from the AFU and save it for future use
 * @scm_data: the SCM metadata
 * Return: 0 on success, negative on failure
 */
static int scm_setup_device_metadata(struct scm_data *scm_data)
{
	u64 val;
	int rc;
	int i;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, GLOBAL_MMIO_CCAP0,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	scm_data->scm_revision = val & 0xFFFF;
	scm_data->read_latency = (val >> 32) & 0xFF;
	scm_data->readiness_timeout = val >> 48;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, GLOBAL_MMIO_CCAP1,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	scm_data->max_controller_dump_size = val & 0xFFFFFFFF;

	rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, GLOBAL_MMIO_FWVER,
				     OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	for (i = 0; i < 8; i++)
		scm_data->fw_version[i] = (val >> (i * 8)) & 0xff;

	scm_data->fw_version[8] = '\0';

	dev_info(&scm_data->dev,
		 "Firmware version '%s' SCM revision %d:%d\n", scm_data->fw_version,
		 scm_data->scm_revision >> 4, scm_data->scm_revision & 0x0F);

	return 0;
}

static const char *scm_decode_error_log_type(u8 error_log_type)
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

static void scm_dump_error_log(struct scm_data *scm_data)
{
	struct scm_ioctl_error_log log;
	u32 buf_size;
	u8 *buf;
	int rc;

	if (scm_data->admin_command.data_size == 0)
		return;

	buf_size = scm_data->admin_command.data_size - 0x48;
	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return;

	log.buf = buf;
	log.buf_size = buf_size;

	rc = scm_read_error_log(scm_data, &log, false);
	if (rc < 0)
		goto out;

	dev_warn(&scm_data->dev,
		 "SCM Error log: WWID=0x%016llx%016llx LID=0x%x PRC=%x type=0x%x %s, Uptime=%u seconds timestamp=0x%llx\n",
		 log.wwid[0], log.wwid[1],
		 log.log_identifier, log.program_reference_code,
		 log.error_log_type,
		 scm_decode_error_log_type(log.error_log_type),
		 log.power_on_seconds, log.timestamp);
	print_hex_dump(KERN_WARNING, "buf", DUMP_PREFIX_OFFSET, 16, 1, buf,
		       log.buf_size, false);

out:
	kfree(buf);
}

static void scm_handle_nscra_doorbell(struct scm_data *scm_data)
{
	int rc;

	if (scm_data->ns_command.op_code == NS_COMMAND_SECURE_ERASE) {
		u64 success, attempted;


		rc = scm_ns_response(scm_data);
		if (rc < 0) {
			scm_data->overwrite_state = SCM_OVERWRITE_FAILED;
			mutex_unlock(&scm_data->ns_command.lock);
			return;
		}
		if (rc != STATUS_SUCCESS)
			scm_warn_status(scm_data, "Unexpected status from overwrite", rc);

		rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
					     scm_data->ns_command.response_offset +
					     NS_RESPONSE_SECURE_ERASE_ACCESSIBLE_SUCCESS,
					     OCXL_HOST_ENDIAN, &success);
		if (rc) {
			scm_data->overwrite_state = SCM_OVERWRITE_FAILED;
			mutex_unlock(&scm_data->ns_command.lock);
			return;
		}

		rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
					     scm_data->ns_command.response_offset +
					     NS_RESPONSE_SECURE_ERASE_ACCESSIBLE_ATTEMPTED,
					     OCXL_HOST_ENDIAN, &attempted);
		if (rc) {
			scm_data->overwrite_state = SCM_OVERWRITE_FAILED;
			mutex_unlock(&scm_data->ns_command.lock);
			return;
		}

		scm_data->overwrite_state = SCM_OVERWRITE_SUCCESS;
		if (success != attempted)
			scm_data->overwrite_state = SCM_OVERWRITE_FAILED;

		dev_info(&scm_data->dev,
			 "Overwritten %llu/%llu accessible pages", success, attempted);

		rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
					     scm_data->ns_command.response_offset +
					     NS_RESPONSE_SECURE_ERASE_DEFECTIVE_SUCCESS,
					     OCXL_HOST_ENDIAN, &success);
		if (rc) {
			scm_data->overwrite_state = SCM_OVERWRITE_FAILED;
			mutex_unlock(&scm_data->ns_command.lock);
			return;
		}

		rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
					     scm_data->ns_command.response_offset +
					     NS_RESPONSE_SECURE_ERASE_DEFECTIVE_ATTEMPTED,
					     OCXL_HOST_ENDIAN, &attempted);
		if (rc) {
			scm_data->overwrite_state = SCM_OVERWRITE_FAILED;
			mutex_unlock(&scm_data->ns_command.lock);
			return;
		}

		if (success != attempted)
			scm_data->overwrite_state = SCM_OVERWRITE_FAILED;

		dev_info(&scm_data->dev,
			 "Overwritten %llu/%llu defective pages", success, attempted);

		scm_ns_response_handled(scm_data);

		mutex_unlock(&scm_data->ns_command.lock);
		return;
	}
}

static irqreturn_t scm_imn0_handler(void *private)
{
	struct scm_data *scm_data = private;
	int rc;
	u64 chi = 0;

	rc = scm_chi(scm_data, &chi);
	if (rc < 0)
		return IRQ_NONE;

	if (chi & GLOBAL_MMIO_CHI_NSCRA)
		scm_handle_nscra_doorbell(scm_data);

	if (chi & GLOBAL_MMIO_CHI_ELA) {
		dev_warn(&scm_data->dev, "Error log is available\n");

		if (scm_data->ev_ctx)
			eventfd_signal(scm_data->ev_ctx, 1);
	}

	if (chi & GLOBAL_MMIO_CHI_CDA) {
		dev_warn(&scm_data->dev, "Controller dump is available\n");

		if (scm_data->ev_ctx)
			eventfd_signal(scm_data->ev_ctx, 1);
	}


	return IRQ_HANDLED;
}

static irqreturn_t scm_imn1_handler(void *private)
{
	struct scm_data *scm_data = private;
	u64 chi = 0;

	(void)scm_chi(scm_data, &chi);

	if (chi & (GLOBAL_MMIO_CHI_CFFS | GLOBAL_MMIO_CHI_CHFS)) {
		dev_err(&scm_data->dev,
			"Controller status is fatal, chi=0x%llx, going offline\n", chi);

		if (scm_data->nvdimm_bus) {
			nvdimm_bus_unregister(scm_data->nvdimm_bus);
			scm_data->nvdimm_bus = NULL;
		}

		if (scm_data->ev_ctx)
			eventfd_signal(scm_data->ev_ctx, 1);
	}

	return IRQ_HANDLED;
}


/**
 * scm_setup_irq() - Set up the IRQs for the SCM device
 * @scm_data: the SCM metadata
 * Return: 0 on success, negative on failure
 */
static int scm_setup_irq(struct scm_data *scm_data)
{
	int rc;
	u64 irq_addr;

	rc = ocxl_afu_irq_alloc(scm_data->ocxl_context, &scm_data->irq_id[0]);
	if (rc)
		return rc;

	rc = ocxl_irq_set_handler(scm_data->ocxl_context, scm_data->irq_id[0],
				  scm_imn0_handler, NULL, scm_data);

	irq_addr = ocxl_afu_irq_get_addr(scm_data->ocxl_context, scm_data->irq_id[0]);
	if (!irq_addr)
		return -EFAULT;

	scm_data->irq_addr[0] = ioremap(irq_addr, PAGE_SIZE);
	if (!scm_data->irq_addr[0])
		return -EINVAL;

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu, GLOBAL_MMIO_IMA0_OHP,
				      OCXL_LITTLE_ENDIAN,
				      (u64)scm_data->irq_addr[0]);
	if (rc)
		goto out_irq0;

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu, GLOBAL_MMIO_IMA0_CFP,
				      OCXL_LITTLE_ENDIAN, 0);
	if (rc)
		goto out_irq0;

	rc = ocxl_afu_irq_alloc(scm_data->ocxl_context, &scm_data->irq_id[1]);
	if (rc)
		goto out_irq0;


	rc = ocxl_irq_set_handler(scm_data->ocxl_context, scm_data->irq_id[1],
				  scm_imn1_handler, NULL, scm_data);
	if (rc)
		goto out_irq0;

	irq_addr = ocxl_afu_irq_get_addr(scm_data->ocxl_context, scm_data->irq_id[1]);
	if (!irq_addr)
		goto out_irq0;

	scm_data->irq_addr[1] = ioremap(irq_addr, PAGE_SIZE);
	if (!scm_data->irq_addr[1])
		goto out_irq0;

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu, GLOBAL_MMIO_IMA1_OHP,
				      OCXL_LITTLE_ENDIAN,
				      (u64)scm_data->irq_addr[1]);
	if (rc)
		goto out_irq1;

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu, GLOBAL_MMIO_IMA1_CFP,
				      OCXL_LITTLE_ENDIAN, 0);
	if (rc)
		goto out_irq1;

	// Enable doorbells
	rc = ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_CHIE,
				    OCXL_LITTLE_ENDIAN,
				    GLOBAL_MMIO_CHI_ELA | GLOBAL_MMIO_CHI_CDA |
				    GLOBAL_MMIO_CHI_CFFS | GLOBAL_MMIO_CHI_CHFS |
				    GLOBAL_MMIO_CHI_NSCRA);
	if (rc)
		goto out_irq1;

	return 0;

out_irq1:
	iounmap(scm_data->irq_addr[1]);
	scm_data->irq_addr[1] = NULL;

out_irq0:
	iounmap(scm_data->irq_addr[0]);
	scm_data->irq_addr[0] = NULL;

	return rc;
}

/**
 * scm_probe_function_0 - Set up function 0 for an OpenCAPI Storage Class Memory device
 * This is important as it enables higher than 0 across all other functions,
 * which in turn enables higher bandwidth accesses
 * @pdev: the PCI device information struct
 * Return: 0 on success, negative on failure
 */
static int scm_probe_function_0(struct pci_dev *pdev)
{
	struct scm_function_0 *scm_func_0 = NULL;

	scm_func_0 = kzalloc(sizeof(*scm_func_0), GFP_KERNEL);
	if (!scm_func_0)
		return -ENOMEM;

	scm_func_0->pdev = pdev;
	scm_func_0->ocxl_fn = ocxl_function_open(pdev);
	if (IS_ERR(scm_func_0->ocxl_fn)) {
		kfree(scm_func_0);
		dev_err(&pdev->dev, "failed to open OCXL function\n");
		return -EFAULT;
	}

	pci_set_drvdata(pdev, scm_func_0);

	return 0;
}

/**
 * scm_probe - Init an OpenCAPI Storage Class Memory device
 * @pdev: the PCI device information struct
 * @ent: The entry from scm_pci_tbl
 * Return: 0 on success, negative on failure
 */
static int scm_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct scm_data *scm_data = NULL;
	int elapsed;
	u64 chi;

	if (PCI_FUNC(pdev->devfn) == 0)
		return scm_probe_function_0(pdev);
	else if (PCI_FUNC(pdev->devfn) != 1)
		return 0;

	scm_data = kzalloc(sizeof(*scm_data), GFP_KERNEL);
	if (!scm_data)
		goto err;
	scm_data->pdev = pdev;
	mutex_init(&scm_data->admin_command.lock);
	mutex_init(&scm_data->ns_command.lock);


	scm_data->timeouts[ADMIN_COMMAND_ERRLOG] = 2000; // ms
	scm_data->timeouts[ADMIN_COMMAND_HEARTBEAT] = 100; // ms
	scm_data->timeouts[ADMIN_COMMAND_SMART] = 100; // ms
	scm_data->timeouts[ADMIN_COMMAND_CONTROLLER_DUMP] = 1000; // ms
	scm_data->timeouts[ADMIN_COMMAND_CONTROLLER_STATS] = 100; // ms
	scm_data->timeouts[ADMIN_COMMAND_SHUTDOWN] = 1000; // ms
	scm_data->timeouts[ADMIN_COMMAND_FW_UPDATE] = 16000; // ms

	pci_set_drvdata(pdev, scm_data);

	scm_data->ocxl_fn = ocxl_function_open(pdev);
	if (IS_ERR(scm_data->ocxl_fn)) {
		kfree(scm_data);
		scm_data = NULL;
		pci_set_drvdata(pdev, NULL);
		dev_err(&pdev->dev, "failed to open OCXL function\n");
		goto err;
	}

	scm_data->ocxl_afu = ocxl_function_fetch_afu(scm_data->ocxl_fn, 0);
	if (scm_data->ocxl_afu == NULL)
		goto err;

	ocxl_afu_get(scm_data->ocxl_afu);

	if (scm_register(scm_data) < 0)
		goto err;

	if (ocxl_context_alloc(&scm_data->ocxl_context, scm_data->ocxl_afu, NULL))
		goto err;

	if (ocxl_context_attach(scm_data->ocxl_context, 0, NULL))
		goto err;

	if (scm_setup_device_metadata(scm_data))
		goto err;

	if (scm_setup_irq(scm_data))
		goto err;

	if (scm_setup_command_metadata(scm_data))
		goto err;

	if (scm_create_cdev(scm_data))
		goto err;

	if (scm_sysfs_add(scm_data))
		goto err;

	if (scm_heartbeat(scm_data))
		goto err;

	elapsed = 0;
	while (!scm_is_usable(scm_data)) {
		if (elapsed++ > SCM_USABLE_TIMEOUT) {
			dev_warn(&scm_data->dev, "SCM ready timeout.\n");
			goto err;
		}

		dev_warn(&scm_data->dev,
			 "Waiting for SCM to become usable (%d/%d seconds)\n",
			 elapsed, SCM_USABLE_TIMEOUT);
		msleep(1000);
	}

	if (scm_register_lpc_mem(scm_data))
		goto err;

	return 0;

err:
	if (scm_data &&
		    (scm_chi(scm_data, &chi) == 0) &&
		    (chi & GLOBAL_MMIO_CHI_ELA))
		scm_dump_error_log(scm_data);

	dev_err(&pdev->dev,
		"Error detected, will not register storage class memory\n");
	return -ENXIO;
}

struct pci_driver scm_pci_driver = {
	.name = "ocxl-scm",
	.id_table = scm_pci_tbl,
	.probe = scm_probe,
	.remove = scm_remove,
	.shutdown = scm_remove,
};

static int scm_file_init(void)
{
	int rc;

	mutex_init(&minors_idr_lock);
	idr_init(&minors_idr);

	rc = alloc_chrdev_region(&scm_dev, 0, SCM_NUM_MINORS, "scm");
	if (rc) {
		pr_err("Unable to allocate scm major number: %d\n", rc);
		return rc;
	}

	scm_class = class_create(THIS_MODULE, "scm");
	if (IS_ERR(scm_class)) {
		pr_err("Unable to create scm class\n");
		unregister_chrdev_region(scm_dev, SCM_NUM_MINORS);
		return PTR_ERR(scm_class);
	}

	return 0;
}

static void scm_file_exit(void)
{
	class_destroy(scm_class);
	unregister_chrdev_region(scm_dev, SCM_NUM_MINORS);
	idr_destroy(&minors_idr);
}

static int __init scm_init(void)
{
	int rc = 0;

	rc = scm_file_init();
	if (rc)
		return rc;

	rc = pci_register_driver(&scm_pci_driver);
	if (rc) {
		scm_file_exit();
		return rc;
	}

	return 0;
}

static void scm_exit(void)
{
	pci_unregister_driver(&scm_pci_driver);
	scm_file_exit();
}

module_init(scm_init);
module_exit(scm_exit);

MODULE_DESCRIPTION("Storage Class Memory");
MODULE_LICENSE("GPL");
