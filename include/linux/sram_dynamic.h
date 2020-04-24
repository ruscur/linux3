/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SRAM_DYNAMIC_H
#define __SRAM_DYNAMIC_H

struct sram_api {
	const char	*name;
	struct sram_device *sdev;
	void *(*alloc)(__u32 size, phys_addr_t *phys, __u32 align);
	void (*free)(void *ptr);
};

int __must_check
	__sram_register_device(struct module *owner,
			       struct device *parent,
			       struct sram_api *sa);

/* Use a define to avoid include chaining to get THIS_MODULE */
#define sram_register_device(parent, sa) \
	__sram_register_device(THIS_MODULE, parent, sa)

void sram_unregister_device(struct sram_api *sa);

#endif /* __SRAM_DYNAMIC_H */
