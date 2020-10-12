/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *
 * Copyright IBM Corp. 2020
 *
 * Authors: Ram Pai <linuxram@us.ibm.com>
 */

#ifndef __POWERPC_KVMPPC_SVM_BACKEND_H__
#define __POWERPC_KVMPPC_SVM_BACKEND_H__

#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/bug.h>
#ifdef CONFIG_PPC_BOOK3S
#include <asm/kvm_book3s.h>
#else
#include <asm/kvm_booke.h>
#endif
#ifdef CONFIG_KVM_BOOK3S_64_HANDLER
#include <asm/paca.h>
#include <asm/xive.h>
#include <asm/cpu_has_feature.h>
#endif

struct kvmppc_hmm_backend {
	/* initialize */
	int (*kvmppc_secmem_init)(void);

	/* cleanup */
	void (*kvmppc_secmem_free)(void);

	/* is memory available */
	bool (*kvmppc_secmem_available)(void);

	/* allocate a protected/secure page for the secure VM */
	unsigned long (*kvmppc_svm_page_in)(struct kvm *kvm,
			unsigned long gra,
			unsigned long flags,
			unsigned long page_shift);

	/* recover the protected/secure page from the secure VM */
	unsigned long (*kvmppc_svm_page_out)(struct kvm *kvm,
			unsigned long gra,
			unsigned long flags,
			unsigned long page_shift);

	/* initiate the transition of a VM to secure VM */
	unsigned long (*kvmppc_svm_init_start)(struct kvm *kvm);

	/* finalize the transition of a secure VM */
	unsigned long (*kvmppc_svm_init_done)(struct kvm *kvm);

	/* share the page on page fault */
	int (*kvmppc_svm_page_share)(struct kvm *kvm, unsigned long gfn);

	/* abort the transition to a secure VM */
	unsigned long (*kvmppc_svm_init_abort)(struct kvm *kvm);

	/* add a memory slot */
	int (*kvmppc_svm_memslot_create)(struct kvm *kvm,
		const struct kvm_memory_slot *new);

	/* free a memory slot */
	void (*kvmppc_svm_memslot_delete)(struct kvm *kvm,
		const struct kvm_memory_slot *old);

	/* drop pages allocated to the secure VM */
	void (*kvmppc_svm_drop_pages)(const struct kvm_memory_slot *free,
			     struct kvm *kvm, bool skip_page_out);
};

extern const struct kvmppc_hmm_backend *kvmppc_svm_backend;

static inline int kvmppc_svm_page_share(struct kvm *kvm, unsigned long gfn)
{
	if (!kvmppc_svm_backend)
		return -ENODEV;

	return kvmppc_svm_backend->kvmppc_svm_page_share(kvm,
				gfn);
}

static inline void kvmppc_svm_drop_pages(const struct kvm_memory_slot *memslot,
			struct kvm *kvm, bool skip_page_out)
{
	if (!kvmppc_svm_backend)
		return;

	kvmppc_svm_backend->kvmppc_svm_drop_pages(memslot,
			kvm, skip_page_out);
}

static inline int kvmppc_svm_page_in(struct kvm *kvm,
			unsigned long gpa,
			unsigned long flags,
			unsigned long page_shift)
{
	if (!kvmppc_svm_backend)
		return -ENODEV;

	return kvmppc_svm_backend->kvmppc_svm_page_in(kvm,
			gpa, flags, page_shift);
}

static inline int kvmppc_svm_page_out(struct kvm *kvm,
			unsigned long gpa,
			unsigned long flags,
			unsigned long page_shift)
{
	if (!kvmppc_svm_backend)
		return -ENODEV;

	return kvmppc_svm_backend->kvmppc_svm_page_out(kvm,
			gpa, flags, page_shift);
}

static inline int kvmppc_svm_init_start(struct kvm *kvm)
{
	if (!kvmppc_svm_backend)
		return -ENODEV;

	return kvmppc_svm_backend->kvmppc_svm_init_start(kvm);
}

static inline int kvmppc_svm_init_done(struct kvm *kvm)
{
	if (!kvmppc_svm_backend)
		return -ENODEV;

	return kvmppc_svm_backend->kvmppc_svm_init_done(kvm);
}

static inline int kvmppc_svm_init_abort(struct kvm *kvm)
{
	if (!kvmppc_svm_backend)
		return -ENODEV;

	return kvmppc_svm_backend->kvmppc_svm_init_abort(kvm);
}

static inline void kvmppc_svm_memslot_create(struct kvm *kvm,
		const struct kvm_memory_slot *memslot)
{
	if (!kvmppc_svm_backend)
		return;

	kvmppc_svm_backend->kvmppc_svm_memslot_create(kvm,
			memslot);
}

static inline void kvmppc_svm_memslot_delete(struct kvm *kvm,
		const struct kvm_memory_slot *memslot)
{
	if (!kvmppc_svm_backend)
		return;

	kvmppc_svm_backend->kvmppc_svm_memslot_delete(kvm,
			memslot);
}

static inline int kvmppc_secmem_init(void)
{
#ifdef CONFIG_PPC_UV
	extern const struct kvmppc_hmm_backend kvmppc_uvmem_backend;

	kvmppc_svm_backend = NULL;
	if (kvmhv_on_pseries()) {
		/* @TODO add the protected memory backend */
		return 0;
	}

	kvmppc_svm_backend = &kvmppc_uvmem_backend;

	if (!kvmppc_svm_backend->kvmppc_secmem_init) {
		pr_err("KVM-HV: kvmppc_svm_backend has no %s\n", __func__);
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_secmem_free) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_secmem_free()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_secmem_available) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_secmem_available()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_page_in) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_page_in()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_page_out) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_page_out()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_init_start) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_init_start()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_init_done) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_init_done()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_page_share) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_page_share()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_init_abort) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_init_abort()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_memslot_create) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_memslot_create()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_memslot_delete) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_memslot_delete()\n");
		goto err;
	}
	if (!kvmppc_svm_backend->kvmppc_svm_drop_pages) {
		pr_err("KVM-HV: kvmppc_svm_backend has no kvmppc_svm_drop_pages()\n");
		goto err;
	}

	return kvmppc_svm_backend->kvmppc_secmem_init();

err:	kvmppc_svm_backend = NULL;
	return -ENODEV;
#endif
	return 0;
}

static inline void kvmppc_secmem_free(void)
{
	if (!kvmppc_svm_backend)
		return;

	return kvmppc_svm_backend->kvmppc_secmem_free();
}

static inline int kvmppc_secmem_available(void)
{
	if (!kvmppc_svm_backend)
		return 0;

	return kvmppc_svm_backend->kvmppc_secmem_available();
}
#endif /* __POWERPC_KVMPPC_SVM_BACKEND_H__ */
