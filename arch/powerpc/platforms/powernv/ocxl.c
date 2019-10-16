// SPDX-License-Identifier: GPL-2.0+
// Copyright 2017 IBM Corp.
#include <asm/pnv-ocxl.h>
#include <asm/opal.h>
#include <asm/xive.h>
#include <misc/ocxl-config.h>
#include "pci.h"

#define PNV_OCXL_TL_P9_RECV_CAP		0x000000000000000Full
#define PNV_OCXL_ACTAG_MAX		64
/* PASIDs are 20-bit, but on P9, NPU can only handle 15 bits */
#define PNV_OCXL_PASID_BITS		15
#define PNV_OCXL_PASID_MAX		((1 << PNV_OCXL_PASID_BITS) - 1)

#define AFU_PRESENT	(1 << 31)
#define AFU_INDEX_MASK	0x3F000000
#define AFU_INDEX_SHIFT	24
#define ACTAG_MASK	0xFFF

#define SPA_PASID_BITS		15
#define SPA_PASID_MAX		((1 << SPA_PASID_BITS) - 1)
#define SPA_PE_MASK		SPA_PASID_MAX
#define SPA_SPA_SIZE_LOG	22 /* Each SPA is 4 Mb */
#define SPA_PE_VALID		0x80000000

#define SPA_CFG_SF		(1ull << (63 - 0))
#define SPA_CFG_TA		(1ull << (63 - 1))
#define SPA_CFG_HV		(1ull << (63 - 3))
#define SPA_CFG_UV		(1ull << (63 - 4))
#define SPA_CFG_XLAT_hpt	(0ull << (63 - 6)) /* Hashed page table (HPT) mode */
#define SPA_CFG_XLAT_roh	(2ull << (63 - 6)) /* Radix on HPT mode */
#define SPA_CFG_XLAT_ror	(3ull << (63 - 6)) /* Radix on Radix mode */
#define SPA_CFG_PR		(1ull << (63 - 49))
#define SPA_CFG_TC		(1ull << (63 - 54))
#define SPA_CFG_DR		(1ull << (63 - 59))

struct ocxl_process_element {
	__be64 config_state;
	__be32 reserved1[11];
	__be32 lpid;
	__be32 tid;
	__be32 pid;
	__be32 reserved2[10];
	__be64 amr;
	__be32 reserved3[3];
	__be32 software_state;
};

struct spa {
	struct ocxl_process_element *spa_mem;
	int spa_order;
};

struct platform_data {
	struct spa *spa;
	u64 phb_opal_id;
	u32 bdfn;
	void __iomem *dsisr;
	void __iomem *dar;
	void __iomem *tfc;
	void __iomem *pe_handle;
};

struct actag_range {
	u16 start;
	u16 count;
};

struct npu_link {
	struct list_head list;
	int domain;
	int bus;
	int dev;
	u16 fn_desired_actags[8];
	struct actag_range fn_actags[8];
	bool assignment_done;
};
static struct list_head links_list = LIST_HEAD_INIT(links_list);
static DEFINE_MUTEX(links_list_lock);


/*
 * opencapi actags handling:
 *
 * When sending commands, the opencapi device references the memory
 * context it's targeting with an 'actag', which is really an alias
 * for a (BDF, pasid) combination. When it receives a command, the NPU
 * must do a lookup of the actag to identify the memory context. The
 * hardware supports a finite number of actags per link (64 for
 * POWER9).
 *
 * The device can carry multiple functions, and each function can have
 * multiple AFUs. Each AFU advertises in its config space the number
 * of desired actags. The host must configure in the config space of
 * the AFU how many actags the AFU is really allowed to use (which can
 * be less than what the AFU desires).
 *
 * When a PCI function is probed by the driver, it has no visibility
 * about the other PCI functions and how many actags they'd like,
 * which makes it impossible to distribute actags fairly among AFUs.
 *
 * Unfortunately, the only way to know how many actags a function
 * desires is by looking at the data for each AFU in the config space
 * and add them up. Similarly, the only way to know how many actags
 * all the functions of the physical device desire is by adding the
 * previously computed function counts. Then we can match that against
 * what the hardware supports.
 *
 * To get a comprehensive view, we use a 'pci fixup': at the end of
 * PCI enumeration, each function counts how many actags its AFUs
 * desire and we save it in a 'npu_link' structure, shared between all
 * the PCI functions of a same device. Therefore, when the first
 * function is probed by the driver, we can get an idea of the total
 * count of desired actags for the device, and assign the actags to
 * the AFUs, by pro-rating if needed.
 */

static int find_dvsec_from_pos(struct pci_dev *dev, int dvsec_id, int pos)
{
	int vsec = pos;
	u16 vendor, id;

	while ((vsec = pci_find_next_ext_capability(dev, vsec,
						    OCXL_EXT_CAP_ID_DVSEC))) {
		pci_read_config_word(dev, vsec + OCXL_DVSEC_VENDOR_OFFSET,
				&vendor);
		pci_read_config_word(dev, vsec + OCXL_DVSEC_ID_OFFSET, &id);
		if (vendor == PCI_VENDOR_ID_IBM && id == dvsec_id)
			return vsec;
	}
	return 0;
}

static int find_dvsec_afu_ctrl(struct pci_dev *dev, u8 afu_idx)
{
	int vsec = 0;
	u8 idx;

	while ((vsec = find_dvsec_from_pos(dev, OCXL_DVSEC_AFU_CTRL_ID,
					   vsec))) {
		pci_read_config_byte(dev, vsec + OCXL_DVSEC_AFU_CTRL_AFU_IDX,
				&idx);
		if (idx == afu_idx)
			return vsec;
	}
	return 0;
}

static int get_max_afu_index(struct pci_dev *dev, int *afu_idx)
{
	int pos;
	u32 val;

	pos = find_dvsec_from_pos(dev, OCXL_DVSEC_FUNC_ID, 0);
	if (!pos)
		return -ESRCH;

	pci_read_config_dword(dev, pos + OCXL_DVSEC_FUNC_OFF_INDEX, &val);
	if (val & AFU_PRESENT)
		*afu_idx = (val & AFU_INDEX_MASK) >> AFU_INDEX_SHIFT;
	else
		*afu_idx = -1;
	return 0;
}

static int get_actag_count(struct pci_dev *dev, int afu_idx, int *actag)
{
	int pos;
	u16 actag_sup;

	pos = find_dvsec_afu_ctrl(dev, afu_idx);
	if (!pos)
		return -ESRCH;

	pci_read_config_word(dev, pos + OCXL_DVSEC_AFU_CTRL_ACTAG_SUP,
			&actag_sup);
	*actag = actag_sup & ACTAG_MASK;
	return 0;
}

static struct npu_link *find_link(struct pci_dev *dev)
{
	struct npu_link *link;

	list_for_each_entry(link, &links_list, list) {
		/* The functions of a device all share the same link */
		if (link->domain == pci_domain_nr(dev->bus) &&
			link->bus == dev->bus->number &&
			link->dev == PCI_SLOT(dev->devfn)) {
			return link;
		}
	}

	/* link doesn't exist yet. Allocate one */
	link = kzalloc(sizeof(struct npu_link), GFP_KERNEL);
	if (!link)
		return NULL;
	link->domain = pci_domain_nr(dev->bus);
	link->bus = dev->bus->number;
	link->dev = PCI_SLOT(dev->devfn);
	list_add(&link->list, &links_list);
	return link;
}

static void pnv_ocxl_fixup_actag(struct pci_dev *dev)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	struct npu_link *link;
	int rc, afu_idx = -1, i, actag;

	if (!machine_is(powernv))
		return;

	if (phb->type != PNV_PHB_NPU_OCAPI)
		return;

	mutex_lock(&links_list_lock);

	link = find_link(dev);
	if (!link) {
		dev_warn(&dev->dev, "couldn't update actag information\n");
		mutex_unlock(&links_list_lock);
		return;
	}

	/*
	 * Check how many actags are desired for the AFUs under that
	 * function and add it to the count for the link
	 */
	rc = get_max_afu_index(dev, &afu_idx);
	if (rc) {
		/* Most likely an invalid config space */
		dev_dbg(&dev->dev, "couldn't find AFU information\n");
		afu_idx = -1;
	}

	link->fn_desired_actags[PCI_FUNC(dev->devfn)] = 0;
	for (i = 0; i <= afu_idx; i++) {
		/*
		 * AFU index 'holes' are allowed. So don't fail if we
		 * can't read the actag info for an index
		 */
		rc = get_actag_count(dev, i, &actag);
		if (rc)
			continue;
		link->fn_desired_actags[PCI_FUNC(dev->devfn)] += actag;
	}
	dev_dbg(&dev->dev, "total actags for function: %d\n",
		link->fn_desired_actags[PCI_FUNC(dev->devfn)]);

	mutex_unlock(&links_list_lock);
}
DECLARE_PCI_FIXUP_HEADER(PCI_ANY_ID, PCI_ANY_ID, pnv_ocxl_fixup_actag);

static u16 assign_fn_actags(u16 desired, u16 total)
{
	u16 count;

	if (total <= PNV_OCXL_ACTAG_MAX)
		count = desired;
	else
		count = PNV_OCXL_ACTAG_MAX * desired / total;

	return count;
}

static void assign_actags(struct npu_link *link)
{
	u16 actag_count, range_start = 0, total_desired = 0;
	int i;

	for (i = 0; i < 8; i++)
		total_desired += link->fn_desired_actags[i];

	for (i = 0; i < 8; i++) {
		if (link->fn_desired_actags[i]) {
			actag_count = assign_fn_actags(
				link->fn_desired_actags[i],
				total_desired);
			link->fn_actags[i].start = range_start;
			link->fn_actags[i].count = actag_count;
			range_start += actag_count;
			WARN_ON(range_start >= PNV_OCXL_ACTAG_MAX);
		}
		pr_debug("link %x:%x:%x fct %d actags: start=%d count=%d (desired=%d)\n",
			link->domain, link->bus, link->dev, i,
			link->fn_actags[i].start, link->fn_actags[i].count,
			link->fn_desired_actags[i]);
	}
	link->assignment_done = true;
}

int pnv_ocxl_get_actag(struct pci_dev *dev, u16 *base, u16 *enabled,
		u16 *supported)
{
	struct npu_link *link;

	mutex_lock(&links_list_lock);

	link = find_link(dev);
	if (!link) {
		dev_err(&dev->dev, "actag information not found\n");
		mutex_unlock(&links_list_lock);
		return -ENODEV;
	}
	/*
	 * On p9, we only have 64 actags per link, so they must be
	 * shared by all the functions of the same adapter. We counted
	 * the desired actag counts during PCI enumeration, so that we
	 * can allocate a pro-rated number of actags to each function.
	 */
	if (!link->assignment_done)
		assign_actags(link);

	*base      = link->fn_actags[PCI_FUNC(dev->devfn)].start;
	*enabled   = link->fn_actags[PCI_FUNC(dev->devfn)].count;
	*supported = link->fn_desired_actags[PCI_FUNC(dev->devfn)];

	mutex_unlock(&links_list_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_get_actag);

int pnv_ocxl_get_pasid_count(struct pci_dev *dev, int *count)
{
	struct npu_link *link;
	int i, rc = -EINVAL;

	/*
	 * The number of PASIDs (process address space ID) which can
	 * be used by a function depends on how many functions exist
	 * on the device. The NPU needs to be configured to know how
	 * many bits are available to PASIDs and how many are to be
	 * used by the function BDF indentifier.
	 *
	 * We only support one AFU-carrying function for now.
	 */
	mutex_lock(&links_list_lock);

	link = find_link(dev);
	if (!link) {
		dev_err(&dev->dev, "actag information not found\n");
		mutex_unlock(&links_list_lock);
		return -ENODEV;
	}

	for (i = 0; i < 8; i++)
		if (link->fn_desired_actags[i] && (i == PCI_FUNC(dev->devfn))) {
			*count = PNV_OCXL_PASID_MAX;
			rc = 0;
			break;
		}

	mutex_unlock(&links_list_lock);
	dev_dbg(&dev->dev, "%d PASIDs available for function\n",
		rc ? 0 : *count);
	return rc;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_get_pasid_count);

static void set_templ_rate(unsigned int templ, unsigned int rate, char *buf)
{
	int shift, idx;

	WARN_ON(templ > PNV_OCXL_TL_MAX_TEMPLATE);
	idx = (PNV_OCXL_TL_MAX_TEMPLATE - templ) / 2;
	shift = 4 * (1 - ((PNV_OCXL_TL_MAX_TEMPLATE - templ) % 2));
	buf[idx] |= rate << shift;
}

int pnv_ocxl_get_tl_cap(struct pci_dev *dev, long *cap,
			char *rate_buf, int rate_buf_size)
{
	if (rate_buf_size != PNV_OCXL_TL_RATE_BUF_SIZE)
		return -EINVAL;
	/*
	 * The TL capabilities are a characteristic of the NPU, so
	 * we go with hard-coded values.
	 *
	 * The receiving rate of each template is encoded on 4 bits.
	 *
	 * On P9:
	 * - templates 0 -> 3 are supported
	 * - templates 0, 1 and 3 have a 0 receiving rate
	 * - template 2 has receiving rate of 1 (extra cycle)
	 */
	memset(rate_buf, 0, rate_buf_size);
	set_templ_rate(2, 1, rate_buf);
	*cap = PNV_OCXL_TL_P9_RECV_CAP;
	return 0;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_get_tl_cap);

int pnv_ocxl_set_tl_conf(struct pci_dev *dev, long cap,
			uint64_t rate_buf_phys, int rate_buf_size)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	int rc;

	if (rate_buf_size != PNV_OCXL_TL_RATE_BUF_SIZE)
		return -EINVAL;

	rc = opal_npu_tl_set(phb->opal_id, dev->devfn, cap,
			rate_buf_phys, rate_buf_size);
	if (rc) {
		dev_err(&dev->dev, "Can't configure host TL: %d\n", rc);
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_set_tl_conf);

static int get_xsl_irq(struct pci_dev *dev, int *hwirq)
{
	int rc;

	rc = of_property_read_u32(dev->dev.of_node, "ibm,opal-xsl-irq", hwirq);
	if (rc) {
		dev_err(&dev->dev,
			"Can't get translation interrupt for device\n");
		return rc;
	}
	return 0;
}

static void unmap_xsl_regs(void __iomem *dsisr, void __iomem *dar,
			   void __iomem *tfc, void __iomem *pe_handle)
{
	iounmap(dsisr);
	iounmap(dar);
	iounmap(tfc);
	iounmap(pe_handle);
}

static int map_xsl_regs(struct pci_dev *dev, void __iomem **dsisr,
			void __iomem **dar, void __iomem **tfc,
			void __iomem **pe_handle)
{
	u64 reg;
	int i, j, rc = 0;
	void __iomem *regs[4];

	/*
	 * opal stores the mmio addresses of the DSISR, DAR, TFC and
	 * PE_HANDLE registers in a device tree property, in that
	 * order
	 */
	for (i = 0; i < 4; i++) {
		rc = of_property_read_u64_index(dev->dev.of_node,
						"ibm,opal-xsl-mmio", i, &reg);
		if (rc)
			break;
		regs[i] = ioremap(reg, 8);
		if (!regs[i]) {
			rc = -EINVAL;
			break;
		}
	}
	if (rc) {
		dev_err(&dev->dev, "Can't map translation mmio registers\n");
		for (j = i - 1; j >= 0; j--)
			iounmap(regs[j]);
	} else {
		*dsisr = regs[0];
		*dar = regs[1];
		*tfc = regs[2];
		*pe_handle = regs[3];
	}
	return rc;
}

static int alloc_spa(struct pci_dev *dev, struct platform_data *data)
{
	struct spa *spa;

	spa = kzalloc(sizeof(*spa), GFP_KERNEL);
	if (!spa)
		return -ENOMEM;

	spa->spa_order = SPA_SPA_SIZE_LOG - PAGE_SHIFT;
	spa->spa_mem = (struct ocxl_process_element *)
		__get_free_pages(GFP_KERNEL | __GFP_ZERO, spa->spa_order);
	if (!spa->spa_mem) {
		dev_err(&dev->dev, "Can't allocate Shared Process Area\n");
		kfree(spa);
		return -ENOMEM;
	}

	data->spa = spa;
	dev_dbg(&dev->dev, "Allocated SPA for %x:%x:%x at %p\n",
		pci_domain_nr(dev->bus), dev->bus->number,
		PCI_SLOT(dev->devfn), spa->spa_mem);

	return 0;
}

static void free_spa(struct platform_data *data)
{
	struct spa *spa = data->spa;

	if (spa && spa->spa_mem) {
		free_pages((unsigned long)spa->spa_mem, spa->spa_order);
		kfree(spa);
		data->spa = NULL;
	}
}

int pnv_ocxl_platform_setup(struct pci_dev *dev, int PE_mask,
			    int *hwirq, void **platform_data)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	struct platform_data *data;
	int xsl_irq;
	u32 bdfn;
	int rc;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	rc = alloc_spa(dev, data);
	if (rc) {
		kfree(data);
		return rc;
	}

	rc = get_xsl_irq(dev, &xsl_irq);
	if (rc) {
		free_spa(data);
		kfree(data);
		return rc;
	}

	rc = map_xsl_regs(dev, &data->dsisr, &data->dar, &data->tfc,
			  &data->pe_handle);
	if (rc) {
		free_spa(data);
		kfree(data);
		return rc;
	}

	bdfn = (dev->bus->number << 8) | dev->devfn;
	rc = opal_npu_spa_setup(phb->opal_id, bdfn,
				virt_to_phys(data->spa->spa_mem),
				PE_mask);
	if (rc) {
		dev_err(&dev->dev, "Can't setup Shared Process Area: %d\n", rc);
		unmap_xsl_regs(data->dsisr, data->dar, data->tfc,
			       data->pe_handle);
		free_spa(data);
		kfree(data);
		return rc;
	}
	data->phb_opal_id = phb->opal_id;
	data->bdfn = bdfn;
	*platform_data = (void *) data;

	*hwirq = xsl_irq;
	return 0;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_platform_setup);

void pnv_ocxl_get_fault_state(void *platform_data, u64 *dsisr, u64 *dar,
			      u64 *pe_handle, int *pid)
{
	struct platform_data *data = (struct platform_data *)platform_data;
	struct ocxl_process_element *pe;

	*dsisr = in_be64(data->dsisr);
	*dar = in_be64(data->dar);
	*pe_handle = in_be64(data->pe_handle) & SPA_PE_MASK;

	pe = data->spa->spa_mem + *pe_handle;
	*pid = be32_to_cpu(pe->pid);
}
EXPORT_SYMBOL_GPL(pnv_ocxl_get_fault_state);

void pnv_ocxl_handle_fault(void *platform_data, u64 tfc)
{
	struct platform_data *data = (struct platform_data *)platform_data;

	out_be64(data->tfc, tfc);
}
EXPORT_SYMBOL_GPL(pnv_ocxl_handle_fault);

void pnv_ocxl_platform_release(void *platform_data)
{
	struct platform_data *data = (struct platform_data *)platform_data;
	int rc;

	rc = opal_npu_spa_setup(data->phb_opal_id, data->bdfn, 0, 0);
	WARN_ON(rc);
	unmap_xsl_regs(data->dsisr, data->dar, data->tfc, data->pe_handle);
	free_spa(data);
	kfree(data);
}
EXPORT_SYMBOL_GPL(pnv_ocxl_platform_release);

int pnv_ocxl_alloc_xive_irq(u32 *irq, u64 *trigger_addr)
{
	__be64 flags, trigger_page;
	s64 rc;
	u32 hwirq;

	hwirq = xive_native_alloc_irq();
	if (!hwirq)
		return -ENOENT;

	rc = opal_xive_get_irq_info(hwirq, &flags, NULL, &trigger_page, NULL,
				NULL);
	if (rc || !trigger_page) {
		xive_native_free_irq(hwirq);
		return -ENOENT;
	}
	*irq = hwirq;
	*trigger_addr = be64_to_cpu(trigger_page);
	return 0;

}
EXPORT_SYMBOL_GPL(pnv_ocxl_alloc_xive_irq);

void pnv_ocxl_free_xive_irq(u32 irq)
{
	xive_native_free_irq(irq);
}
EXPORT_SYMBOL_GPL(pnv_ocxl_free_xive_irq);

static u64 calculate_cfg_state(u32 lpid, bool kernel)
{
	u64 state;

	state = SPA_CFG_DR;
	if (mfspr(SPRN_LPCR) & LPCR_TC)
		state |= SPA_CFG_TC;
	if (radix_enabled())
		state |= SPA_CFG_XLAT_ror;
	else
		state |= SPA_CFG_XLAT_hpt;
	if (lpid == 0)
		state |= SPA_CFG_HV;
	if (kernel) {
		if (mfmsr() & MSR_SF)
			state |= SPA_CFG_SF;
	} else {
		state |= SPA_CFG_PR;
		if (!test_tsk_thread_flag(current, TIF_32BIT))
			state |= SPA_CFG_SF;
	}
	return state;
}

int pnv_ocxl_set_pe(void *platform_data, int lpid, int pasid, u32 pidr,
		    u32 tidr, u64 amr, int *pe_handle)
{
	struct platform_data *data = (struct platform_data *)platform_data;
	struct spa *spa = data->spa;
	struct ocxl_process_element *pe;

	BUILD_BUG_ON(sizeof(struct ocxl_process_element) != 128);
	if (pasid > SPA_PASID_MAX)
		return -EINVAL;

	*pe_handle = pasid & SPA_PE_MASK;
	pe = spa->spa_mem + *pe_handle;

	if (pe->software_state)
		return -EBUSY;

	memset(pe, 0, sizeof(struct ocxl_process_element));
	pe->config_state = cpu_to_be64(calculate_cfg_state(lpid, pidr == 0));
	pe->lpid = cpu_to_be32(lpid);
	pe->pid = cpu_to_be32(pidr);
	pe->tid = cpu_to_be32(tidr);
	pe->amr = cpu_to_be64(amr);
	pe->software_state = cpu_to_be32(SPA_PE_VALID);

	return 0;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_set_pe);

static int remove_pe_from_cache(void *platform_data, int pe_handle)
{
	struct platform_data *data = (struct platform_data *)platform_data;
	int rc;

	/*
	 * The barrier makes sure the PE is updated/removed
	 * before we clear the NPU context cache below, so that the
	 * old PE cannot be reloaded erroneously.
	 */
	mb();

	/*
	 * On powerpc, the entry needs to be cleared from the context
	 * cache of the NPU.
	 */
	rc = opal_npu_spa_clear_cache(data->phb_opal_id, data->bdfn,
				      pe_handle);
	WARN_ON(rc);

	return rc;
}

int pnv_ocxl_update_pe(void *platform_data, int pasid, __u16 tid)
{
	struct platform_data *data = (struct platform_data *)platform_data;
	struct spa *spa = data->spa;
	struct ocxl_process_element *pe;
	int pe_handle;

	if (pasid > SPA_PASID_MAX)
		return -EINVAL;

	pe_handle = pasid & SPA_PE_MASK;
	pe = spa->spa_mem + pe_handle;
	pe->tid = cpu_to_be32(tid);

	return remove_pe_from_cache(data, pe_handle);
}
EXPORT_SYMBOL_GPL(pnv_ocxl_update_pe);

int pnv_ocxl_remove_pe(void *platform_data, int pasid, u32 *pid,
		       u32 *tid, int *pe_handle)
{
	struct platform_data *data = (struct platform_data *)platform_data;
	struct spa *spa = data->spa;
	struct ocxl_process_element *pe;

	if (pasid > SPA_PASID_MAX)
		return -EINVAL;

	*pe_handle = pasid & SPA_PE_MASK;
	pe = spa->spa_mem + *pe_handle;

	if (!(be32_to_cpu(pe->software_state) & SPA_PE_VALID))
		return -EINVAL;

	*pid = be32_to_cpu(pe->pid);
	*tid = be32_to_cpu(pe->tid);

	memset(pe, 0, sizeof(struct ocxl_process_element));

	return remove_pe_from_cache(data, *pe_handle);
}
EXPORT_SYMBOL_GPL(pnv_ocxl_remove_pe);
