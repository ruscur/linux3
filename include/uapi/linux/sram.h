/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SRAM_H
#define __SRAM_H

/* Allocate memory resource from SRAM */
#define SRAM_UAPI_IOC_ALLOC	_IOWR('S', 0, __be64)

/* Free allocated memory resource to SRAM */
#define SRAM_UAPI_IOC_FREE	_IO('S', 1)

#endif /* __SRAM_H */
