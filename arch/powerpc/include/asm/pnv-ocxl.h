/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright 2017 IBM Corp.
#ifndef _ASM_PNV_OCXL_H
#define _ASM_PNV_OCXL_H

#include <linux/pci.h>

#define PNV_OCXL_TL_MAX_TEMPLATE        63
#define PNV_OCXL_TL_BITS_PER_RATE       4
#define PNV_OCXL_TL_RATE_BUF_SIZE       ((PNV_OCXL_TL_MAX_TEMPLATE+1) * PNV_OCXL_TL_BITS_PER_RATE / 8)

int pnv_ocxl_get_actag(struct pci_dev *dev, u16 *base,
		       u16 *enabled, u16 *supported);
int pnv_ocxl_get_pasid_count(struct pci_dev *dev, int *count);

int pnv_ocxl_set_TL(struct pci_dev *dev, int tl_dvsec);

int pnv_ocxl_platform_setup(struct pci_dev *dev,
			    int PE_mask, int *hwirq,
			    void **platform_data);
void pnv_ocxl_platform_release(void *platform_data);

void pnv_ocxl_get_fault_state(void *platform_data, u64 *dsisr,
			      u64 *dar, u64 *pe, int *pid);
void pnv_ocxl_handle_fault(void *platform_data, u64 tfc);

int pnv_ocxl_alloc_xive_irq(u32 *irq, u64 *trigger_addr);
void pnv_ocxl_free_xive_irq(u32 irq);

int pnv_ocxl_set_pe(void *platform_data, int lpid, int pasid,
		    u32 pidr, u32 tidr, u64 amr, int *pe_handle);
int pnv_ocxl_update_pe(void *platform_data, int pasid, __u16 tid);
int pnv_ocxl_remove_pe(void *platform_data, int pasid, u32 *pid,
		       u32 *tid, int *pe_handle);

#endif /* _ASM_PNV_OCXL_H */
