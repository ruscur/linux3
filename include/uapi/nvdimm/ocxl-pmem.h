/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* Copyright 2017 IBM Corp. */
#ifndef _UAPI_OCXL_SCM_H
#define _UAPI_OCXL_SCM_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define OCXL_PMEM_ERROR_LOG_ACTION_RESET	(1 << (32-32))
#define OCXL_PMEM_ERROR_LOG_ACTION_CHKFW	(1 << (53-32))
#define OCXL_PMEM_ERROR_LOG_ACTION_REPLACE	(1 << (54-32))
#define OCXL_PMEM_ERROR_LOG_ACTION_DUMP		(1 << (55-32))

#define OCXL_PMEM_ERROR_LOG_TYPE_GENERAL		(0x00)
#define OCXL_PMEM_ERROR_LOG_TYPE_PREDICTIVE_FAILURE	(0x01)
#define OCXL_PMEM_ERROR_LOG_TYPE_THERMAL_WARNING	(0x02)
#define OCXL_PMEM_ERROR_LOG_TYPE_DATA_LOSS		(0x03)
#define OCXL_PMEM_ERROR_LOG_TYPE_HEALTH_PERFORMANCE	(0x04)

struct ioctl_ocxl_pmem_error_log {
	__u32 log_identifier; /* out */
	__u32 program_reference_code; /* out */
	__u32 action_flags; /* out, recommended course of action */
	__u32 power_on_seconds; /* out, Number of seconds the controller has been on when the error occurred */
	__u64 timestamp; /* out, relative time since the current IPL */
	__u64 wwid[2]; /* out, the NAA formatted WWID associated with the controller */
	char  fw_revision[8+1]; /* out, firmware revision as null terminated text */
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
	__u8 *buf; /* pointer to output buffer */
};

struct ioctl_ocxl_pmem_controller_dump_data {
	__u8 *buf; /* pointer to output buffer */
	__u16 buf_size; /* in/out, buffer size provided/required.
			 * If required is greater than provided, the buffer
			 * will be truncated to the amount provided. If its
			 * less, then only the required bytes will be populated.
			 * If it is 0, then there is no more dump data available.
			 */
	__u32 offset; /* in, Offset within the dump */
	__u64 reserved[8];
};

struct ioctl_ocxl_pmem_controller_stats {
	__u32 reset_count;
	__u32 reset_uptime; /* seconds */
	__u32 power_on_uptime; /* seconds */
	__u64 host_load_count;
	__u64 host_store_count;
	__u64 media_read_count;
	__u64 media_write_count;
	__u64 cache_hit_count;
	__u64 cache_miss_count;
	__u64 media_read_latency; /* nanoseconds */
	__u64 media_write_latency; /* nanoseconds */
	__u64 cache_read_latency; /* nanoseconds */
	__u64 cache_write_latency; /* nanoseconds */
};

struct ioctl_ocxl_pmem_eventfd {
	__s32 eventfd;
	__u32 reserved;
};

#ifndef BIT_ULL
#define BIT_ULL(nr)	(1ULL << (nr))
#endif

#define IOCTL_OCXL_PMEM_EVENT_CONTROLLER_DUMP_AVAILABLE	BIT_ULL(0)
#define IOCTL_OCXL_PMEM_EVENT_ERROR_LOG_AVAILABLE	BIT_ULL(1)
#define IOCTL_OCXL_PMEM_EVENT_HARDWARE_FATAL		BIT_ULL(2)
#define IOCTL_OCXL_PMEM_EVENT_FIRMWARE_FATAL		BIT_ULL(3)

/* ioctl numbers */
#define OCXL_PMEM_MAGIC 0x5C
/* SCM devices */
#define IOCTL_OCXL_PMEM_ERROR_LOG			_IOWR(OCXL_PMEM_MAGIC, 0x01, struct ioctl_ocxl_pmem_error_log)
#define IOCTL_OCXL_PMEM_CONTROLLER_DUMP			_IO(OCXL_PMEM_MAGIC, 0x02)
#define IOCTL_OCXL_PMEM_CONTROLLER_DUMP_DATA		_IOWR(OCXL_PMEM_MAGIC, 0x03, struct ioctl_ocxl_pmem_controller_dump_data)
#define IOCTL_OCXL_PMEM_CONTROLLER_DUMP_COMPLETE	_IO(OCXL_PMEM_MAGIC, 0x04)
#define IOCTL_OCXL_PMEM_CONTROLLER_STATS		_IO(OCXL_PMEM_MAGIC, 0x05)
#define IOCTL_OCXL_PMEM_EVENTFD				_IOW(OCXL_PMEM_MAGIC, 0x06, struct ioctl_ocxl_pmem_eventfd)
#define IOCTL_OCXL_PMEM_EVENT_CHECK			_IOR(OCXL_PMEM_MAGIC, 0x07, __u64)

#endif /* _UAPI_OCXL_SCM_H */
