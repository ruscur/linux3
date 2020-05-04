// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Microsoft Corporation.
 *
 * Authors:
 * Prakhar Srivastava <prsriva@linux.microsoft.com>
 */

#include <linux/kexec.h>
#include <linux/of.h>


/**
 * is_ima_memory_reserved - check if memory is reserved via device
 *			    tree.
 *	Return: negative or zero when memory is not reserved.
 *	positive number on success.
 *
 */
int is_ima_memory_reserved(void)
{
	return of_is_ima_memory_reserved();
}

/**
 * ima_get_kexec_buffer - get IMA buffer from the previous kernel
 * @addr:	On successful return, set to point to the buffer contents.
 * @size:	On successful return, set to the buffer size.
 *
 * Return: 0 on success, negative errno on error.
 */
int ima_get_kexec_buffer(void **addr, size_t *size)
{
	return of_get_ima_buffer(addr, size);
}

/**
 * ima_free_kexec_buffer - free memory used by the IMA buffer
 *
 * Return: 0 on success, negative errno on error.
 */
int ima_free_kexec_buffer(void)
{
	return of_remove_ima_buffer();
}

#ifdef CONFIG_IMA_KEXEC
/**
 * arch_ima_add_kexec_buffer - do arch-specific steps to add the IMA
 *	measurement log.
 * @image: - pointer to the kimage, to store the address and size of the
 *	IMA measurement log.
 * @load_addr: - the address where the IMA measurement log is stored.
 * @size - size of the IMA measurement log.
 *
 * Return: 0 on success, negative errno on error.
 */
int arch_ima_add_kexec_buffer(struct kimage *image, unsigned long load_addr,
			      void *buffer, size_t size)
{
	of_ima_write_buffer(buffer, size);
	return 0;
}
#endif /* CONFIG_IMA_KEXEC */
