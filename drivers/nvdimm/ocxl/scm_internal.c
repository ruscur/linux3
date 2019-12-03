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

static int scm_command_request(const struct scm_data *scm_data,
			       struct command_metadata *cmd, u8 op_code)
{
	u64 val = op_code;
	int rc;
	u8 i;

	cmd->op_code = op_code;
	cmd->id++;

	val |= ((u64)cmd->id) << 16;

	rc = ocxl_global_mmio_write64(scm_data->ocxl_afu, cmd->request_offset,
				      OCXL_LITTLE_ENDIAN, val);
	if (rc)
		return rc;

	for (i = 0x08; i <= 0x38; i += 0x08) {
		rc = ocxl_global_mmio_write64(scm_data->ocxl_afu,
					      cmd->request_offset + i,
					      OCXL_LITTLE_ENDIAN, 0);
		if (rc)
			return rc;
	}

	return 0;
}

int scm_admin_command_request(struct scm_data *scm_data, u8 op_code)
{
	u64 val;
	int rc = ocxl_global_mmio_read64(scm_data->ocxl_afu, GLOBAL_MMIO_CHI,
					 OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	return scm_command_request(scm_data, &scm_data->admin_command, op_code);
}

static int scm_command_response(const struct scm_data *scm_data,
			 const struct command_metadata *cmd)
{
	u64 val;
	u16 id;
	u8 status;
	int rc = ocxl_global_mmio_read64(scm_data->ocxl_afu,
					 cmd->response_offset,
					 OCXL_LITTLE_ENDIAN, &val);
	if (rc)
		return rc;

	status = val & 0xff;
	id = (val >> 16) & 0xffff;

	if (id != cmd->id) {
		dev_warn(&scm_data->dev,
			 "Expected response for command %d, but received response for command %d instead.\n",
			 cmd->id, id);
	}

	return status;
}

int scm_admin_response(const struct scm_data *scm_data)
{
	return scm_command_response(scm_data, &scm_data->admin_command);
}


int scm_admin_command_execute(const struct scm_data *scm_data)
{
	return ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_HCI,
				      OCXL_LITTLE_ENDIAN, GLOBAL_MMIO_HCI_ACRW);
}

static bool scm_admin_command_complete(const struct scm_data *scm_data)
{
	u64 val = 0;

	int rc = scm_chi(scm_data, &val);

	WARN_ON(rc);

	return (val & GLOBAL_MMIO_CHI_ACRA) != 0;
}

int scm_admin_command_complete_timeout(const struct scm_data *scm_data,
				       int command)
{
	u32 timeout = scm_data->timeouts[command];
	// 32 is the next power of 2 greater than the 20ms minimum for msleep
#define TIMEOUT_SLEEP_MILLIS 32
	timeout /= TIMEOUT_SLEEP_MILLIS;
	if (!timeout)
		timeout = SCM_DEFAULT_TIMEOUT / TIMEOUT_SLEEP_MILLIS;

	while (timeout-- > 0) {
		if (scm_admin_command_complete(scm_data))
			return 0;
		msleep(TIMEOUT_SLEEP_MILLIS);
	}

	if (scm_admin_command_complete(scm_data))
		return 0;

	return -EBUSY;
}

int scm_admin_response_handled(const struct scm_data *scm_data)
{
	return ocxl_global_mmio_set64(scm_data->ocxl_afu, GLOBAL_MMIO_CHIC,
				      OCXL_LITTLE_ENDIAN, GLOBAL_MMIO_CHI_ACRA);
}

void scm_warn_status(const struct scm_data *scm_data, const char *message,
		     u8 status)
{
	const char *text = "Unknown";

	switch (status) {
	case STATUS_SUCCESS:
		text = "Success";
		break;

	case STATUS_MEM_UNAVAILABLE:
		text = "Persistent memory unavailable";
		break;

	case STATUS_BAD_OPCODE:
		text = "Bad opcode";
		break;

	case STATUS_BAD_REQUEST_PARM:
		text = "Bad request parameter";
		break;

	case STATUS_BAD_DATA_PARM:
		text = "Bad data parameter";
		break;

	case STATUS_DEBUG_BLOCKED:
		text = "Debug action blocked";
		break;

	case STATUS_FAIL:
		text = "Failed";
		break;
	}

	dev_warn(&scm_data->dev, "%s: %s (%x)\n", message, text, status);
}
