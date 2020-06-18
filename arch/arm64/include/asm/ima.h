/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARCH_IMA_H
#define _ASM_ARCH_IMA_H

struct kimage;

#ifdef CONFIG_IMA_KEXEC
int arch_ima_add_kexec_buffer(struct kimage *image, unsigned long load_addr,
			      size_t size);
#else
static inline int arch_ima_add_kexec_buffer(struct kimage *image,
			unsigned long load_addr, size_t size)
{
	return 0;
}
#endif /* CONFIG_IMA_KEXEC */
#endif /* _ASM_ARCH_IMA_H */
