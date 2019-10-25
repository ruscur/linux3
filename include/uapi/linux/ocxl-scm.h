/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* Copyright 2017 IBM Corp. */
#ifndef _UAPI_OCXL_SCM_H
#define _UAPI_OCXL_SCM_H

#include <linux/types.h>
#include <linux/ioctl.h>

enum scm_fwdebug_action {
	SCM_FWDEBUG_READ_CONTROLLER_MEMORY = 0x01,
	SCM_FWDEBUG_WRITE_CONTROLLER_MEMORY = 0x02,
	SCM_FWDEBUG_ENABLE_FUNCTION = 0x03,
	SCM_FWDEBUG_DISABLE_FUNCTION = 0x04,
	SCM_FWDEBUG_GET_PEL = 0x05, // Retrieve Persistent Error Log
};

struct scm_ioctl_buffer_info {
	__u32	admin_command_buffer_size; // out
	__u32	near_storage_buffer_size; // out
};

struct scm_ioctl_fwdebug { // All args are inputs
	enum scm_fwdebug_action debug_action;
	__u16 function_code;
	__u16 buf_size; // Size of optional data buffer
	__u64 debug_parameter_1;
	__u64 debug_parameter_2;
	__u8 *buf; // Pointer to optional in/out data buffer
};

#define SCM_ERROR_LOG_ACTION_RESET	(1 << (32-32))
#define SCM_ERROR_LOG_ACTION_CHKFW	(1 << (53-32))
#define SCM_ERROR_LOG_ACTION_REPLACE	(1 << (54-32))
#define SCM_ERROR_LOG_ACTION_DUMP	(1 << (55-32))

#define SCM_ERROR_LOG_TYPE_GENERAL		(0x00)
#define SCM_ERROR_LOG_TYPE_PREDICTIVE_FAILURE	(0x01)
#define SCM_ERROR_LOG_TYPE_THERMAL_WARNING	(0x02)
#define SCM_ERROR_LOG_TYPE_DATA_LOSS		(0x03)
#define SCM_ERROR_LOG_TYPE_HEALTH_PERFORMANCE	(0x04)

struct scm_ioctl_error_log {
	__u32 log_identifier; // out
	__u32 program_reference_code; // out
	__u32 action_flags; //out, recommended course of action
	__u32 power_on_seconds; // out, Number of seconds the controller has been on when the error occurred
	__u64 timestamp; // out, relative time since the current IPL
	__u64 wwid[2]; // out, the NAA formatted WWID associated with the controller
	char  fw_revision[8+1]; // out, firmware revision as null terminated text
	__u16 buf_size; /* in/out, buffer size provided/required.
			 * If required is greater than provided, the buffer
			 * will be truncated to the amount provided. If its
			 * less, then only the required bytes will be populated.
			 * If it is 0, then there are no more error log entries.
			 */
	__u8  error_log_type;
	__u8  reserved1;
	__u32 reserved2;
	__u64 reserved3[2];
	__u8 *buf; // pointer to output buffer
};

struct scm_ioctl_controller_dump_data {
	__u8 *buf; // pointer to output buffer
	__u16 buf_size; /* in/out, buffer size provided/required.
			 * If required is greater than provided, the buffer
			 * will be truncated to the amount provided. If its
			 * less, then only the required bytes will be populated.
			 * If it is 0, then there is no more dump data available.
			 */
	__u32 offset; // in, Offset within the dump
	__u64 reserved[8];
};

struct scm_ioctl_controller_stats {
	__u32 reset_count;
	__u32 reset_uptime; // seconds
	__u32 power_on_uptime; // seconds
	__u64 host_load_count;
	__u64 host_store_count;
	__u64 media_read_count;
	__u64 media_write_count;
	__u64 cache_hit_count;
	__u64 cache_miss_count;
	__u64 media_read_latency; // nanoseconds
	__u64 media_write_latency; // nanoseconds
	__u64 cache_read_latency; // nanoseconds
	__u64 cache_write_latency; // nanoseconds
};

struct scm_ioctl_mmio {
	__u64 address; // Offset in global MMIO space
	__u64 val; // value to write/was read
};

struct scm_ioctl_eventfd {
	__s32 eventfd;
	__u32 reserved;
};

#ifndef BIT_ULL
#define BIT_ULL(nr)	(1ULL << (nr))
#endif

#define SCM_IOCTL_EVENT_CONTROLLER_DUMP_AVAILABLE	BIT_ULL(0)
#define SCM_IOCTL_EVENT_ERROR_LOG_AVAILABLE		BIT_ULL(1)
#define SCM_IOCTL_EVENT_HARDWARE_FATAL			BIT_ULL(2)
#define SCM_IOCTL_EVENT_FIRMWARE_FATAL			BIT_ULL(3)

/* ioctl numbers */
#define SCM_MAGIC 0x5C
/* SCM devices */
#define SCM_IOCTL_BUFFER_INFO	_IOR(SCM_MAGIC, 0x00, struct scm_ioctl_buffer_info)
#define SCM_IOCTL_ERROR_LOG	_IOWR(SCM_MAGIC, 0x01, struct scm_ioctl_error_log)
#define SCM_IOCTL_CONTROLLER_DUMP _IO(SCM_MAGIC, 0x02)
#define SCM_IOCTL_CONTROLLER_DUMP_DATA _IOWR(SCM_MAGIC, 0x03, struct scm_ioctl_controller_dump_data)
#define SCM_IOCTL_CONTROLLER_DUMP_COMPLETE _IO(SCM_MAGIC, 0x04)
#define SCM_IOCTL_CONTROLLER_STATS _IO(SCM_MAGIC, 0x05)
#define SCM_IOCTL_EVENTFD	_IOW(SCM_MAGIC, 0x06, struct scm_ioctl_eventfd)
#define SCM_IOCTL_EVENT_CHECK	_IOR(SCM_MAGIC, 0x07, __u64)
#define SCM_IOCTL_REQUEST_HEALTH _IO(SCM_MAGIC, 0x08)

#define SCM_IOCTL_FWDEBUG	_IOWR(SCM_MAGIC, 0xf0, struct scm_ioctl_fwdebug)
#define SCM_IOCTL_MMIO_WRITE	_IOW(SCM_MAGIC, 0xf1, struct scm_ioctl_mmio)
#define SCM_IOCTL_MMIO_READ	_IOWR(SCM_MAGIC, 0xf2, struct scm_ioctl_mmio)
#define SCM_IOCTL_SHUTDOWN	_IO(SCM_MAGIC, 0xf3)

#endif /* _UAPI_OCXL_SCM_H */
