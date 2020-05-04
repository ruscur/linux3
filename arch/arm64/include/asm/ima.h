/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_IMA_H
#define _ASM_ARM64_IMA_H

struct kimage;

int is_ima_memory_reserved(void);
int ima_get_kexec_buffer(void **addr, size_t *size);
int ima_free_kexec_buffer(void);

#ifdef CONFIG_IMA_KEXEC
int arch_ima_add_kexec_buffer(struct kimage *image, unsigned long load_addr,
			      void *buffer, size_t size);

#else
int arch_ima_add_kexec_buffer(struct kimage *image, unsigned long load_addr,
			      void *buffer, size_t size)
{
	return 0;
}
#endif /* CONFIG_IMA_KEXEC */
#endif /* _ASM_ARM64_IMA_H */
