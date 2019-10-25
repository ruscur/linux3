// SPDX-License-Identifier: GPL-2.0+
// Copyright 2018 IBM Corp.

#include <linux/sysfs.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/firmware.h>
#include "ocxl-scm_internal.h"

static ssize_t admin_command_buffer_size_show(struct device *device,
	struct device_attribute *attr,
	char *buf)
{
	struct scm_data *scm_data = container_of(device, struct scm_data, dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n", scm_data->admin_command.data_size);
}

static ssize_t fw_version_show(struct device *device,
			       struct device_attribute *attr, char *buf)
{
	struct scm_data *scm_data = container_of(device, struct scm_data, dev);

	return scnprintf(buf, PAGE_SIZE, "%s\n", scm_data->fw_version);
}

#define SCM_FWUPDATE_BLOCK_SIZE	32768

/**
 * scm_update_firmware() - Write a 32kB block of data to firmware
 * The block may be less than 32kB if it is the last one
 *
 * scm_data the SCM device metadata
 * offset: the offset of the start of the block
 * buf: the block data
 * size: the size of the block
 */
static ssize_t scm_update_firmware(struct scm_data *scm_data, size_t offset,
				   const char *buf, size_t size)
{
	int rc;
	size_t i;
	u64 val;

	if (size > SCM_FWUPDATE_BLOCK_SIZE)
		return -EINVAL;

	rc = scm_admin_command_request(scm_data, ADMIN_COMMAND_FW_UPDATE);
	if (rc)
		return rc;

	val = (((u64)offset) << 32) | size;
	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
				      scm_data->admin_command.request_offset + 8,
				      OCXL_LITTLE_ENDIAN, val);
	if (rc)
		return rc;

	for (i = 0; i < size; i += 8) {
		val = *(u64 *)(buf + i);
		rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
					      scm_data->admin_command.data_offset + i,
					      OCXL_HOST_ENDIAN, val);
		if (rc)
			return rc;
	}

	rc = scm_admin_command_execute(scm_data);
	if (rc)
		return rc;

	rc = scm_admin_command_complete_timeout(scm_data,
						ADMIN_COMMAND_FW_UPDATE);
	if (rc < 0) {
		dev_err(&scm_data->dev, "Firmware update timeout\n");
		return rc;
	}

	rc = scm_admin_response(scm_data);
	if (rc < 0)
		return rc;
	if (rc != STATUS_SUCCESS) {
		scm_warn_status_fw_update(scm_data, "FW Update", rc);
		return rc;
	}

	return 0;
}

/*
 * Parse out a firmware filename from sysfs, retrieve it's contents and write it
 * to the SCM device firmware storage
 */
static ssize_t fw_update_filename_store(struct device *device,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	char path[NAME_MAX+1];
	const char *end;
	const struct firmware *firmware = NULL;
	size_t offset;
	int rc;
	struct scm_data *scm_data = container_of(device, struct scm_data, dev);

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	end = strnchr(buf, size, '\n');
	if (end == NULL)
		end = buf + strnlen(buf, size);

	if ((end - buf) > NAME_MAX) {
		dev_err(device, "Firmware filename '%-.*s' too long\n",
			(int)(end - buf), buf);
		return -EIO;
	}

	memcpy(path, buf, end - buf);
	path[end - buf] = '\0';

	if (request_firmware(&firmware, path, device)) {
		dev_err(device, "Firmware file %s not found\n", path);
		return -EIO;
	}

	if (firmware->size % 8) {
		release_firmware(firmware);
		dev_err(device, "Firmware '%s' should be a multiple of 8 bytes", path);
		return -EINVAL;
	}

	mutex_lock(&scm_data->admin_command.lock);

	for (offset = 0; offset < firmware->size; offset += SCM_FWUPDATE_BLOCK_SIZE) {
		size_t remainder = firmware->size - offset;
		size_t block_size;

		block_size = (remainder > SCM_FWUPDATE_BLOCK_SIZE) ?
			      SCM_FWUPDATE_BLOCK_SIZE : remainder;
		rc = scm_update_firmware(scm_data, offset,
					 firmware->data + offset, block_size);
		if (rc) {
			mutex_unlock(&scm_data->admin_command.lock);
			return -EFAULT;
		}
	}

	mutex_unlock(&scm_data->admin_command.lock);

	return size;
}

/*
 * Trigger a controller dump
 */
static ssize_t controller_dump_store(struct device *device,
				     struct device_attribute *attr,
				     const char *buf, size_t size)
{
	struct scm_data *scm_data = container_of(device, struct scm_data, dev);

	scm_request_controller_dump(scm_data);

	return size;
}

/*
 * Request health & performance data
 */
static ssize_t health_request_store(struct device *device,
				    struct device_attribute *attr,
				    const char *buf, size_t size)
{
	struct scm_data *scm_data = container_of(device, struct scm_data, dev);

	scm_req_controller_health_perf(scm_data);

	return size;
}

/*
 * Overwrite all media
 */
static ssize_t overwrite_store(struct device *device,
			       struct device_attribute *attr,
			       const char *buf, size_t size)
{
	struct scm_data *scm_data = container_of(device, struct scm_data, dev);

	scm_overwrite(scm_data);

	return size;
}

static struct device_attribute scm_attrs[] = {
	__ATTR_RO(admin_command_buffer_size),
	__ATTR_RO(fw_version),
	__ATTR_WO(fw_update_filename),
	__ATTR_WO(controller_dump),
	__ATTR_WO(health_request),
	__ATTR_WO(overwrite),
};

int scm_sysfs_add(struct scm_data *scm_data)
{
	int i, rc;

	for (i = 0; i < ARRAY_SIZE(scm_attrs); i++) {
		rc = device_create_file(&scm_data->dev, &scm_attrs[i]);
		if (rc) {
			for (; --i >= 0;)
				device_remove_file(&scm_data->dev, &scm_attrs[i]);

			return rc;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(scm_sysfs_add);
