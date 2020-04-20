/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SRAM_UAPI_H
#define __SRAM_UAPI_H

/* Set SRAM type to be accessed */
#define SRAM_UAPI_IOC_SET_SRAM_TYPE	_IOW('S', 0, __u32)

/* Allocate resource from SRAM */
#define SRAM_UAPI_IOC_ALLOC		_IOWR('S', 1, struct res_info)

/* Free allocated resource of SRAM */
#define SRAM_UAPI_IOC_FREE		_IOW('S', 2, struct res_info)

struct sram_api {
	struct list_head	list;
	struct kref		kref;
	__u32			type;
	const char		*name;

	long (*sram_alloc)(__u32 size, phys_addr_t *phys, __u32 align);
	void (*sram_free)(void *ptr);
};

extern long sram_api_register(struct sram_api *sa);

extern long sram_api_unregister(struct sram_api *sa);

#endif /* __SRAM_UAPI_H */
