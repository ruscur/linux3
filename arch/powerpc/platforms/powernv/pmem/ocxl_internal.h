// SPDX-License-Identifier: GPL-2.0+
// Copyright 2019 IBM Corp.

#include <linux/pci.h>
#include <linux/cdev.h>
#include <misc/ocxl.h>
#include <linux/libnvdimm.h>
#include <linux/mm.h>

#define LABEL_AREA_SIZE	(1UL << PA_SECTION_SHIFT)
#define DEFAULT_TIMEOUT 100

#define GLOBAL_MMIO_CHI		0x000
#define GLOBAL_MMIO_CHIC	0x008
#define GLOBAL_MMIO_CHIE	0x010
#define GLOBAL_MMIO_CHIEC	0x018
#define GLOBAL_MMIO_HCI		0x020
#define GLOBAL_MMIO_HCIC	0x028
#define GLOBAL_MMIO_IMA0_OHP	0x040
#define GLOBAL_MMIO_IMA0_CFP	0x048
#define GLOBAL_MMIO_IMA1_OHP	0x050
#define GLOBAL_MMIO_IMA1_CFP	0x058
#define GLOBAL_MMIO_ACMA_CREQO	0x100
#define GLOBAL_MMIO_ACMA_CRSPO	0x104
#define GLOBAL_MMIO_ACMA_CDBO	0x108
#define GLOBAL_MMIO_ACMA_CDBS	0x10c
#define GLOBAL_MMIO_NSCMA_CREQO	0x120
#define GLOBAL_MMIO_NSCMA_CRSPO	0x124
#define GLOBAL_MMIO_NSCMA_CDBO	0x128
#define GLOBAL_MMIO_NSCMA_CDBS	0x12c
#define GLOBAL_MMIO_CSTS	0x140
#define GLOBAL_MMIO_FWVER	0x148
#define GLOBAL_MMIO_CCAP0	0x160
#define GLOBAL_MMIO_CCAP1	0x168

#define GLOBAL_MMIO_CHI_ACRA	BIT_ULL(0)
#define GLOBAL_MMIO_CHI_NSCRA	BIT_ULL(1)
#define GLOBAL_MMIO_CHI_CRDY	BIT_ULL(4)
#define GLOBAL_MMIO_CHI_CFFS	BIT_ULL(5)
#define GLOBAL_MMIO_CHI_MA	BIT_ULL(6)
#define GLOBAL_MMIO_CHI_ELA	BIT_ULL(7)
#define GLOBAL_MMIO_CHI_CDA	BIT_ULL(8)
#define GLOBAL_MMIO_CHI_CHFS	BIT_ULL(9)

#define GLOBAL_MMIO_CHI_ALL	(GLOBAL_MMIO_CHI_ACRA | \
				 GLOBAL_MMIO_CHI_NSCRA | \
				 GLOBAL_MMIO_CHI_CRDY | \
				 GLOBAL_MMIO_CHI_CFFS | \
				 GLOBAL_MMIO_CHI_MA | \
				 GLOBAL_MMIO_CHI_ELA | \
				 GLOBAL_MMIO_CHI_CDA | \
				 GLOBAL_MMIO_CHI_CHFS)

#define GLOBAL_MMIO_HCI_ACRW				BIT_ULL(0)
#define GLOBAL_MMIO_HCI_NSCRW				BIT_ULL(1)
#define GLOBAL_MMIO_HCI_AFU_RESET			BIT_ULL(2)
#define GLOBAL_MMIO_HCI_FW_DEBUG			BIT_ULL(3)
#define GLOBAL_MMIO_HCI_CONTROLLER_DUMP			BIT_ULL(4)
#define GLOBAL_MMIO_HCI_CONTROLLER_DUMP_COLLECTED	BIT_ULL(5)
#define GLOBAL_MMIO_HCI_REQ_HEALTH_PERF			BIT_ULL(6)

#define ADMIN_COMMAND_HEARTBEAT		0x00u
#define ADMIN_COMMAND_SHUTDOWN		0x01u
#define ADMIN_COMMAND_FW_UPDATE		0x02u
#define ADMIN_COMMAND_FW_DEBUG		0x03u
#define ADMIN_COMMAND_ERRLOG		0x04u
#define ADMIN_COMMAND_SMART		0x05u
#define ADMIN_COMMAND_CONTROLLER_STATS	0x06u
#define ADMIN_COMMAND_CONTROLLER_DUMP	0x07u
#define ADMIN_COMMAND_CMD_CAPS		0x08u
#define ADMIN_COMMAND_MAX		0x08u

#define STATUS_SUCCESS		0x00
#define STATUS_MEM_UNAVAILABLE	0x20
#define STATUS_BAD_OPCODE	0x50
#define STATUS_BAD_REQUEST_PARM	0x51
#define STATUS_BAD_DATA_PARM	0x52
#define STATUS_DEBUG_BLOCKED	0x70
#define STATUS_FAIL		0xFF

#define STATUS_FW_UPDATE_BLOCKED 0x21
#define STATUS_FW_ARG_INVALID	0x51
#define STATUS_FW_INVALID	0x52

struct command_metadata {
	u32 request_offset;
	u32 response_offset;
	u32 data_offset;
	u32 data_size;
	struct mutex lock;
	u16 id;
	u8 op_code;
};

struct ocxlpmem_function0 {
	struct pci_dev *pdev;
	struct ocxl_fn *ocxl_fn;
};

struct ocxlpmem {
	struct device dev;
	struct pci_dev *pdev;
	struct cdev cdev;
	struct ocxl_fn *ocxl_fn;
	struct nd_interleave_set nd_set;
	struct nvdimm_bus_descriptor bus_desc;
	struct nvdimm_bus *nvdimm_bus;
	struct ocxl_afu *ocxl_afu;
	struct ocxl_context *ocxl_context;
	void *metadata_addr;
	struct command_metadata admin_command;
	struct command_metadata ns_command;
	struct resource pmem_res;
	struct nd_region *nd_region;
	char fw_version[8+1];
	u32 timeouts[ADMIN_COMMAND_MAX+1];

	u32 max_controller_dump_size;
	u16 scm_revision; // major/minor
	u8 readiness_timeout;  /* The worst case time (in seconds) that the host shall
				* wait for the controller to become operational following a reset (CHI.CRDY).
				*/
	u8 memory_available_timeout;   /* The worst case time (in seconds) that the host shall
					* wait for memory to become available following a reset (CHI.MA).
					*/

	u16 read_latency; /* The nominal measure of latency (in nanoseconds)
			   * associated with an unassisted read of a memory block.
			   * This represents the capability of the raw media technology without assistance
			   */
};

/**
 * ocxlpmem_chi() - Get the value of the CHI register
 * @ocxlpmem: the device metadata
 * @chi: returns the CHI value
 *
 * Returns 0 on success, negative on error
 */
int ocxlpmem_chi(const struct ocxlpmem *ocxlpmem, u64 *chi);

/**
 * admin_command_request() - Issue an admin command request
 * @ocxlpmem: the device metadata
 * @op_code: The op-code for the command
 *
 * Returns an identifier for the command, or negative on error
 */
int admin_command_request(struct ocxlpmem *ocxlpmem, u8 op_code);

/**
 * admin_response() - Validate an admin response
 * @ocxlpmem: the device metadata
 * Returns the status code of the command, or negative on error
 */
int admin_response(const struct ocxlpmem *ocxlpmem);

/**
 * admin_command_execute() - Notify the controller to start processing a pending admin command
 * @ocxlpmem: the device metadata
 * Returns 0 on success, negative on error
 */
int admin_command_execute(const struct ocxlpmem *ocxlpmem);

/**
 * admin_command_complete_timeout() - Wait for an admin command to finish executing
 * @ocxlpmem: the device metadata
 * @command: the admin command to wait for completion (determines the timeout)
 * Returns 0 on success, -EBUSY on timeout
 */
int admin_command_complete_timeout(const struct ocxlpmem *ocxlpmem,
				   int command);

/**
 * admin_response_handled() - Notify the controller that the admin response has been handled
 * @ocxlpmem: the device metadata
 * Returns 0 on success, negative on failure
 */
int admin_response_handled(const struct ocxlpmem *ocxlpmem);

/**
 * ns_command_request() - Issue a near storage command request
 * @ocxlpmem: the device metadata
 * @op_code: The op-code for the command
 * Returns an identifier for the command, or negative on error
 */
int ns_command_request(struct ocxlpmem *ocxlpmem, u8 op_code);

/**
 * ns_response() - Validate a near storage response
 * @ocxlpmem: the device metadata
 * Returns the status code of the command, or negative on error
 */
int ns_response(const struct ocxlpmem *ocxlpmem);

/**
 * ns_command_execute() - Notify the controller to start processing a pending near storage command
 * @ocxlpmem: the device metadata
 * Returns 0 on success, negative on error
 */
int ns_command_execute(const struct ocxlpmem *ocxlpmem);

/**
 * ns_command_complete() - Is a near storage command executing
 * @ocxlpmem: the device metadata
 * Returns true if the previous admin command has completed
 */
bool ns_command_complete(const struct ocxlpmem *ocxlpmem);

/**
 * ns_response_handled() - Notify the controller that the near storage response has been handled
 * @ocxlpmem: the device metadata
 * Returns 0 on success, negative on failure
 */
int ns_response_handled(const struct ocxlpmem *ocxlpmem);

/**
 * warn_status() - Emit a kernel warning showing a command status.
 * @ocxlpmem: the device metadata
 * @message: A message to accompany the warning
 * @status: The command status
 */
void warn_status(const struct ocxlpmem *ocxlpmem, const char *message,
		 u8 status);
