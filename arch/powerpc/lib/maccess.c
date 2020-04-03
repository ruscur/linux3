#include <linux/mm.h>
#include <linux/uaccess.h>

/*
 * Override the generic weak linkage functions to avoid changing KUP state via
 * the generic user access functions, as this is accessing kernel addresses.
 */
long probe_kernel_read(void *dst, const void *src, size_t size)
{
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = raw_copy_from_user_allowed(dst, (__force const void __user *)src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}

long probe_kernel_write(void *dst, const void *src, size_t size)
{
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = raw_copy_to_user_allowed((__force void __user *)dst, src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
