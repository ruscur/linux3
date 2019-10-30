// SPDX-License-Identifier: GPL-2.0

#include <linux/dma-mapping.h>
#include <linux/export.h>
#include <linux/pci.h>
#include <asm/machdep.h>

void arch_dma_set_mask(struct device *dev, u64 dma_mask)
{
	if (ppc_md.dma_set_mask)
		ppc_md.dma_set_mask(dev, dma_mask);

	if (dev_is_pci(dev)) {
		struct pci_dev *pdev = to_pci_dev(dev);
		struct pci_controller *phb = pci_bus_to_host(pdev->bus);

		if (phb->controller_ops.dma_set_mask)
			phb->controller_ops.dma_set_mask(pdev, dma_mask);
	}
}
EXPORT_SYMBOL(arch_dma_set_mask);
