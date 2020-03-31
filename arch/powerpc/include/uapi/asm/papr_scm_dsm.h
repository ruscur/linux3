/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * PAPR SCM Device specific methods and struct for libndctl and ndctl
 *
 * (C) Copyright IBM 2020
 *
 * Author: Vaibhav Jain <vaibhav at linux.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_
#define _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_

#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/ndctl.h>
#else
#include <ndctl.h>
#endif

/*
 * DSM Envelope:
 *
 * The ioctl ND_CMD_CALL transfers data between user-space and kernel via
 * 'envelopes' which consists of a header and user-defined payload sections.
 * The header is described by 'struct nd_papr_scm_cmd_pkg' which expects a
 * payload following it and offset of which relative to the struct is provided
 * by 'nd_papr_scm_cmd_pkg.payload_offset'. *
 *
 *  +-------------+---------------------+---------------------------+
 *  |   64-Bytes  |       8-Bytes       |       Max 184-Bytes       |
 *  +-------------+---------------------+---------------------------+
 *  |               nd_papr_scm_cmd_pkg |                           |
 *  |-------------+                     |                           |
 *  |  nd_cmd_pkg |                     |                           |
 *  +-------------+---------------------+---------------------------+
 *  | nd_family   |			|			    |
 *  | nd_size_out | cmd_status          |			    |
 *  | nd_size_in  | payload_version     |      PAYLOAD		    |
 *  | nd_command  | payload_offset ----->			    |
 *  | nd_fw_size  |                     |			    |
 *  +-------------+---------------------+---------------------------+
 *
 * DSM Header:
 *
 * The header is defined as 'struct nd_papr_scm_cmd_pkg' which embeds a
 * 'struct nd_cmd_pkg' instance. The DSM command is assigned to member
 * 'nd_cmd_pkg.nd_command'. Apart from size information of the envelop which is
 * contained in 'struct nd_cmd_pkg', the header also has members following
 * members:
 *
 * 'cmd_status'		: (Out) Errors if any encountered while servicing DSM.
 * 'payload_version'	: (In/Out) Version number associated with the payload.
 * 'payload_offset'	: (In)Relative offset of payload from start of envelope.
 *
 * DSM Payload:
 *
 * The layout of the DSM Payload is defined by various structs shared between
 * papr_scm and libndctl so that contents of payload can be interpreted. During
 * servicing of a DSM the papr_scm module will read input args from the payload
 * field by casting its contents to an appropriate struct pointer based on the
 * DSM command. Similarly the output of servicing the DSM command will be copied
 * to the payload field using the same struct.
 *
 * 'libnvdimm' enforces a hard limit of 256 bytes on the envelope size, which
 * leaves around 184 bytes for the envelope payload (ignoring any padding that
 * the compiler may silently introduce).
 *
 * Payload Version:
 *
 * A 'payload_version' field is present in DSM header that indicates a specific
 * version of the structure present in DSM Payload for a given DSM command. This
 * provides backward compatibility in case the DSM Payload structure evolves
 * and different structures are supported by 'papr_scm' and 'libndctl'.
 *
 * When sending a DSM Payload to 'papr_scm', 'libndctl' should send the version
 * of the payload struct it supports via 'payload_version' field. The 'papr_scm'
 * module when servicing the DSM envelop checks the 'payload_version' and then
 * uses 'payload struct version' == MIN('payload_version field',
 * 'max payload-struct-version supported by papr_scm') to service the DSM. After
 * servicing the DSM, 'papr_scm' put the negotiated version of payload struct in
 * returned 'payload_version' field.
 *
 * Libndctl on receiving the envelop back from papr_scm again checks the
 * 'payload_version' field and based on it use the appropriate version dsm
 * struct to parse the results.
 *
 * Backward Compatibility:
 *
 * Above scheme of exchanging different versioned DSM struct between libndctl
 * and papr_scm should provide backward compatibility until following two
 * assumptions/conditions when defining new DSM structs hold:
 *
 * Let T(X) = { set of attributes in DSM struct 'T' versioned X }
 *
 * 1. T(X) is a proper subset of T(Y) if X > Y.
 *    i.e Each new version of DSM struct should retain existing struct
 *    attributes from previous version
 *
 * 2. If an entity (libndctl or papr_scm) supports a DSM struct T(X) then
 *    it should also support T(1), T(2)...T(X - 1).
 *    i.e When adding support for new version of a DSM struct, libndctl
 *    and papr_scm should retain support of the existing DSM struct
 *    version they support.
 */

/* Papr-scm-header + payload expected with ND_CMD_CALL ioctl from libnvdimm */
struct nd_papr_scm_cmd_pkg {
	struct nd_cmd_pkg hdr;		/* Package header containing sub-cmd */
	__s32 cmd_status;		/* Out: Sub-cmd status returned back */
	__u16 payload_offset;	/* In: offset from start of struct */
	__u16 payload_version;	/* In/Out: version of the payload */
	__u8 payload[];		/* In/Out: Sub-cmd data buffer */
};

/*
 * Sub commands for ND_CMD_CALL. To prevent overlap from ND_CMD_*, values for
 * these enums start at 0x10000. These values are then returned from
 * cmd_to_func() making it easy to implement the switch-case block in
 * papr_scm_ndctl(). These commands are sent to the kernel via
 * 'nd_papr_scm_cmd_pkg.hdr.nd_command'
 */
enum dsm_papr_scm {
	DSM_PAPR_SCM_MIN =  0x10000,
	DSM_PAPR_SCM_MAX,
};

/* Helpers to evaluate the size of PAPR_SCM envelope */
/* Calculate the papr_scm-header size */
#define ND_PAPR_SCM_ENVELOPE_CONTENT_HDR_SIZE \
	(sizeof(struct nd_papr_scm_cmd_pkg) - sizeof(struct nd_cmd_pkg))

/* Given a type calculate envelope-content size (papr_scm-header + payload) */
#define ND_PAPR_SCM_ENVELOPE_CONTENT_SIZE(_type_)	\
	(sizeof(_type_) + ND_PAPR_SCM_ENVELOPE_CONTENT_HDR_SIZE)

/* Convert a libnvdimm nd_cmd_pkg to papr_scm specific pkg */
static struct nd_papr_scm_cmd_pkg *nd_to_papr_cmd_pkg(struct nd_cmd_pkg *cmd)
{
	return (struct nd_papr_scm_cmd_pkg *) cmd;
}

/* Return the payload pointer for a given pcmd */
static void *papr_scm_pcmd_to_payload(struct nd_papr_scm_cmd_pkg *pcmd)
{
	if (pcmd->hdr.nd_size_in == 0 && pcmd->hdr.nd_size_out == 0)
		return NULL;
	else
		return (void *)((__u8 *) pcmd + pcmd->payload_offset);
}
#endif /* _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_ */
