// SPDX-License-Identifier: GPL-2.0+
// Copyright 2017 IBM Corp.
#include <linux/sched/mm.h>
#include <linux/mutex.h>
#include <linux/mm_types.h>
#include <linux/mmu_context.h>
#include <asm/copro.h>
#include <asm/pnv-ocxl.h>
#include <misc/ocxl.h>
#include "ocxl_internal.h"
#include "trace.h"

#define XSL_TF		(1ull << (63 - 3))  /* Translation fault */
#define XSL_S		(1ull << (63 - 38)) /* Store operation */

struct pe_data {
	struct mm_struct *mm;
	/* callback to trigger when a translation fault occurs */
	void (*xsl_err_cb)(void *data, u64 addr, u64 dsisr);
	/* opaque pointer to be passed to the above callback */
	void *xsl_err_data;
	struct rcu_head rcu;
};

/*
 * A opencapi link can be used be by several PCI functions. We have
 * one link per device slot.
 *
 * A linked list of opencapi links should suffice, as there's a
 * limited number of opencapi slots on a system and lookup is only
 * done when the device is probed
 */
struct ocxl_link {
	struct list_head list;
	struct kref ref;
	int domain;
	int bus;
	int dev;
	char *irq_name;
	int virq;
	struct mutex pe_lock;
	atomic_t irq_available;
	void *platform_data;
	struct radix_tree_root pe_tree; /* Maps PE handles to pe_data */

	/*
	 * The following field are used by the memory fault
	 * interrupt handler. We can only have one interrupt at a
	 * time. The NPU won't raise another interrupt until the
	 * previous one has been ack'd by writing to the TFC register
	 */
	struct xsl_fault {
		struct work_struct fault_work;
		u64 pe;
		u64 dsisr;
		u64 dar;
		struct pe_data pe_data;
	} xsl_fault;
};
static struct list_head links_list = LIST_HEAD_INIT(links_list);
static DEFINE_MUTEX(links_list_lock);

enum xsl_response {
	CONTINUE,
	ADDRESS_ERROR,
	RESTART,
};

static void ack_irq(struct ocxl_link *link, enum xsl_response r)
{
	u64 reg = 0;

	/* continue is not supported */
	if (r == RESTART)
		reg = PPC_BIT(31);
	else if (r == ADDRESS_ERROR)
		reg = PPC_BIT(30);
	else
		WARN(1, "Invalid irq response %d\n", r);

	if (reg) {
		trace_ocxl_fault_ack(link->xsl_fault.pe,
				     link->xsl_fault.dsisr,
				     link->xsl_fault.dar,
				     reg);
		pnv_ocxl_handle_fault(link->platform_data, reg);
	}
}

static void xsl_fault_handler_bh(struct work_struct *fault_work)
{
	vm_fault_t flt = 0;
	unsigned long access, flags, inv_flags = 0;
	enum xsl_response r;
	struct xsl_fault *fault = container_of(fault_work, struct xsl_fault,
					fault_work);
	struct ocxl_link *link = container_of(fault, struct ocxl_link, xsl_fault);
	int rc;

	/*
	 * We must release a reference on mm_users whenever exiting this
	 * function (taken in the memory fault interrupt handler)
	 */
	rc = copro_handle_mm_fault(fault->pe_data.mm, fault->dar, fault->dsisr,
				&flt);
	if (rc) {
		pr_debug("copro_handle_mm_fault failed: %d\n", rc);
		if (fault->pe_data.xsl_err_cb) {
			fault->pe_data.xsl_err_cb(
				fault->pe_data.xsl_err_data,
				fault->dar, fault->dsisr);
		}
		r = ADDRESS_ERROR;
		goto ack;
	}

	if (!radix_enabled()) {
		/*
		 * update_mmu_cache() will not have loaded the hash
		 * since current->trap is not a 0x400 or 0x300, so
		 * just call hash_page_mm() here.
		 */
		access = _PAGE_PRESENT | _PAGE_READ;
		if (fault->dsisr & XSL_S)
			access |= _PAGE_WRITE;

		if (get_region_id(fault->dar) != USER_REGION_ID)
			access |= _PAGE_PRIVILEGED;

		local_irq_save(flags);
		hash_page_mm(fault->pe_data.mm, fault->dar, access, 0x300,
			inv_flags);
		local_irq_restore(flags);
	}
	r = RESTART;
ack:
	mmput(fault->pe_data.mm);
	ack_irq(link, r);
}

static irqreturn_t xsl_fault_handler(int irq, void *data)
{
	struct ocxl_link *link = (struct ocxl_link *) data;
	u64 dsisr, dar, pe_handle;
	struct pe_data *pe_data;
	int pid;
	bool schedule = false;

	pnv_ocxl_get_fault_state(link->platform_data, &dsisr, &dar,
				 &pe_handle, &pid);
	trace_ocxl_fault(pe_handle, dsisr, dar, -1);

	/* We could be reading all null values here if the PE is being
	 * removed while an interrupt kicks in. It's not supposed to
	 * happen if the driver notified the AFU to terminate the
	 * PASID, and the AFU waited for pending operations before
	 * acknowledging. But even if it happens, we won't find a
	 * memory context below and fail silently, so it should be ok.
	 */
	if (!(dsisr & XSL_TF)) {
		WARN(1, "Invalid xsl interrupt fault register %#llx\n", dsisr);
		ack_irq(link, ADDRESS_ERROR);
		return IRQ_HANDLED;
	}

	rcu_read_lock();
	pe_data = radix_tree_lookup(&link->pe_tree, pe_handle);
	if (!pe_data) {
		/*
		 * Could only happen if the driver didn't notify the
		 * AFU about PASID termination before removing the PE,
		 * or the AFU didn't wait for all memory access to
		 * have completed.
		 *
		 * Either way, we fail early, but we shouldn't log an
		 * error message, as it is a valid (if unexpected)
		 * scenario
		 */
		rcu_read_unlock();
		pr_debug("Unknown mm context for xsl interrupt\n");
		ack_irq(link, ADDRESS_ERROR);
		return IRQ_HANDLED;
	}

	if (!pe_data->mm) {
		/*
		 * translation fault from a kernel context - an OpenCAPI
		 * device tried to access a bad kernel address
		 */
		rcu_read_unlock();
		pr_warn("Unresolved OpenCAPI xsl fault in kernel context\n");
		ack_irq(link, ADDRESS_ERROR);
		return IRQ_HANDLED;
	}
	WARN_ON(pe_data->mm->context.id != pid);

	if (mmget_not_zero(pe_data->mm)) {
		link->xsl_fault.pe = pe_handle;
		link->xsl_fault.dar = dar;
		link->xsl_fault.dsisr = dsisr;
		link->xsl_fault.pe_data = *pe_data;
		schedule = true;
		/* mm_users count released by bottom half */
	}
	rcu_read_unlock();
	if (schedule)
		schedule_work(&link->xsl_fault.fault_work);
	else
		ack_irq(link, ADDRESS_ERROR);
	return IRQ_HANDLED;
}

static int setup_xsl_irq(struct pci_dev *dev, struct ocxl_link *link,
			 int hwirq)
{
	int rc;

	link->irq_name = kasprintf(GFP_KERNEL, "ocxl-xsl-%x-%x-%x",
				   link->domain, link->bus, link->dev);
	if (!link->irq_name) {
		dev_err(&dev->dev, "Can't allocate name for xsl interrupt\n");
		rc = -ENOMEM;
		goto err_xsl;
	}
	/*
	 * At some point, we'll need to look into allowing a higher
	 * number of interrupts. Could we have an IRQ domain per link?
	 */
	link->virq = irq_create_mapping(NULL, hwirq);
	if (!link->virq) {
		dev_err(&dev->dev,
			"irq_create_mapping failed for translation interrupt\n");
		rc = -EINVAL;
		goto err_name;
	}

	dev_dbg(&dev->dev, "hwirq %d mapped to virq %d\n", hwirq, link->virq);

	rc = request_irq(link->virq, xsl_fault_handler, 0,
			 link->irq_name, link);
	if (rc) {
		dev_err(&dev->dev,
			"request_irq failed for translation interrupt: %d\n",
			rc);
		rc = -EINVAL;
		goto err_mapping;
	}
	return 0;

err_mapping:
	irq_dispose_mapping(link->virq);
err_name:
	kfree(link->irq_name);
err_xsl:
	return rc;
}

static void release_xsl_irq(struct ocxl_link *link)
{
	if (link->virq) {
		free_irq(link->virq, link);
		irq_dispose_mapping(link->virq);
	}
	kfree(link->irq_name);
}

static int alloc_link(struct pci_dev *dev, int PE_mask, struct ocxl_link **out_link)
{
	struct ocxl_link *link;
	int xsl_irq;
	int rc;

	link = kzalloc(sizeof(struct ocxl_link), GFP_KERNEL);
	if (!link)
		return -ENOMEM;

	kref_init(&link->ref);
	link->domain = pci_domain_nr(dev->bus);
	link->bus = dev->bus->number;
	link->dev = PCI_SLOT(dev->devfn);
	atomic_set(&link->irq_available, MAX_IRQ_PER_LINK);
	INIT_WORK(&link->xsl_fault.fault_work, xsl_fault_handler_bh);

	/* platform specific hook */
	rc = pnv_ocxl_platform_setup(dev, PE_mask, &xsl_irq,
				     &link->platform_data);
	if (rc)
		goto err_free;

	mutex_init(&link->pe_lock);
	INIT_RADIX_TREE(&link->pe_tree, GFP_KERNEL);

	rc = setup_xsl_irq(dev, link, xsl_irq);
	if (rc)
		goto err_xsl_irq;

	*out_link = link;
	return 0;

err_xsl_irq:
	pnv_ocxl_platform_release(link->platform_data);
err_free:
	kfree(link);
	return rc;
}

static void free_link(struct ocxl_link *link)
{
	release_xsl_irq(link);
	kfree(link);
}

int ocxl_link_setup(struct pci_dev *dev, int PE_mask, void **link_handle)
{
	int rc = 0;
	struct ocxl_link *link;

	mutex_lock(&links_list_lock);
	list_for_each_entry(link, &links_list, list) {
		/* The functions of a device all share the same link */
		if (link->domain == pci_domain_nr(dev->bus) &&
			link->bus == dev->bus->number &&
			link->dev == PCI_SLOT(dev->devfn)) {
			kref_get(&link->ref);
			*link_handle = link;
			goto unlock;
		}
	}
	rc = alloc_link(dev, PE_mask, &link);
	if (rc)
		goto unlock;

	list_add(&link->list, &links_list);
	*link_handle = link;
unlock:
	mutex_unlock(&links_list_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ocxl_link_setup);

static void release_xsl(struct kref *ref)
{
	struct ocxl_link *link = container_of(ref, struct ocxl_link, ref);

	list_del(&link->list);
	/* call platform code before releasing data */
	pnv_ocxl_platform_release(link->platform_data);
	free_link(link);
}

void ocxl_link_release(struct pci_dev *dev, void *link_handle)
{
	struct ocxl_link *link = (struct ocxl_link *) link_handle;

	mutex_lock(&links_list_lock);
	kref_put(&link->ref, release_xsl);
	mutex_unlock(&links_list_lock);
}
EXPORT_SYMBOL_GPL(ocxl_link_release);

int ocxl_link_add_pe(void *link_handle, int pasid, u32 pidr, u32 tidr,
		u64 amr, struct mm_struct *mm,
		void (*xsl_err_cb)(void *data, u64 addr, u64 dsisr),
		void *xsl_err_data)
{
	struct ocxl_link *link = (struct ocxl_link *) link_handle;
	int pe_handle, rc = 0;
	struct pe_data *pe_data;

	mutex_lock(&link->pe_lock);
	pe_data = kmalloc(sizeof(*pe_data), GFP_KERNEL);
	if (!pe_data) {
		rc = -ENOMEM;
		goto unlock;
	}

	pe_data->mm = mm;
	pe_data->xsl_err_cb = xsl_err_cb;
	pe_data->xsl_err_data = xsl_err_data;

	rc = pnv_ocxl_set_pe(link->platform_data, mfspr(SPRN_LPID),
			     pasid, pidr, tidr, amr, &pe_handle);
	if (rc) {
		kfree(pe_data);
		goto unlock;
	}

	/*
	 * For user contexts, register a copro so that TLBIs are seen
	 * by the nest MMU. If we have a kernel context, TLBIs are
	 * already global.
	 */
	if (mm)
		mm_context_add_copro(mm);
	/*
	 * Barrier is to make sure PE is visible in the SPA before it
	 * is used by the device. It also helps with the global TLBI
	 * invalidation
	 */
	mb();
	radix_tree_insert(&link->pe_tree, pe_handle, pe_data);

	/*
	 * The mm must stay valid for as long as the device uses it. We
	 * lower the count when the context is removed from the SPA.
	 *
	 * We grab mm_count (and not mm_users), as we don't want to
	 * end up in a circular dependency if a process mmaps its
	 * mmio, therefore incrementing the file ref count when
	 * calling mmap(), and forgets to unmap before exiting. In
	 * that scenario, when the kernel handles the death of the
	 * process, the file is not cleaned because unmap was not
	 * called, and the mm wouldn't be freed because we would still
	 * have a reference on mm_users. Incrementing mm_count solves
	 * the problem.
	 */
	if (mm)
		mmgrab(mm);
	trace_ocxl_context_add(current->pid, pasid, pidr, tidr);
unlock:
	mutex_unlock(&link->pe_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ocxl_link_add_pe);

int ocxl_link_update_pe(void *link_handle, int pasid, __u16 tid)
{
	struct ocxl_link *link = (struct ocxl_link *) link_handle;
	int rc;

	mutex_lock(&link->pe_lock);
	rc = pnv_ocxl_update_pe(link->platform_data, pasid, tid);
	mutex_unlock(&link->pe_lock);

	return rc;
}

int ocxl_link_remove_pe(void *link_handle, int pasid)
{
	struct ocxl_link *link = (struct ocxl_link *) link_handle;
	struct pe_data *pe_data;
	int pe_handle, rc;
	u32 pid, tid;

	/*
	 * About synchronization with our memory fault handler:
	 *
	 * Before removing the PE, the driver is supposed to have
	 * notified the AFU, which should have cleaned up and make
	 * sure the PASID is no longer in use, including pending
	 * interrupts. However, there's no way to be sure...
	 *
	 * We clear the PE and remove the context from our radix
	 * tree. From that point on, any new interrupt for that
	 * context will fail silently, which is ok. As mentioned
	 * above, that's not expected, but it could happen if the
	 * driver or AFU didn't do the right thing.
	 *
	 * There could still be a bottom half running, but we don't
	 * need to wait/flush, as it is managing a reference count on
	 * the mm it reads from the radix tree.
	 */
	mutex_lock(&link->pe_lock);

	rc = pnv_ocxl_remove_pe(link->platform_data, pasid, &pid, &tid,
				&pe_handle);
	if (rc)
		goto unlock;

	trace_ocxl_context_remove(current->pid, pasid, pid, tid);

	pe_data = radix_tree_delete(&link->pe_tree, pe_handle);
	if (!pe_data) {
		WARN(1, "Couldn't find pe data when removing PE\n");
	} else {
		if (pe_data->mm) {
			mm_context_remove_copro(pe_data->mm);
			mmdrop(pe_data->mm);
		}
		kfree_rcu(pe_data, rcu);
	}
unlock:
	mutex_unlock(&link->pe_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ocxl_link_remove_pe);

int ocxl_link_irq_alloc(void *link_handle, int *hw_irq, u64 *trigger_addr)
{
	struct ocxl_link *link = (struct ocxl_link *) link_handle;
	int rc, irq;
	u64 addr;

	if (atomic_dec_if_positive(&link->irq_available) < 0)
		return -ENOSPC;

	rc = pnv_ocxl_alloc_xive_irq(&irq, &addr);
	if (rc) {
		atomic_inc(&link->irq_available);
		return rc;
	}

	*hw_irq = irq;
	*trigger_addr = addr;
	return 0;
}
EXPORT_SYMBOL_GPL(ocxl_link_irq_alloc);

void ocxl_link_free_irq(void *link_handle, int hw_irq)
{
	struct ocxl_link *link = (struct ocxl_link *) link_handle;

	pnv_ocxl_free_xive_irq(hw_irq);
	atomic_inc(&link->irq_available);
}
EXPORT_SYMBOL_GPL(ocxl_link_free_irq);
