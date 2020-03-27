#include <linux/mm.h>
#include <linux/uaccess.h>

static __always_inline long
probe_read_common(void *dst, const void __user *src, size_t size)
{
	long ret;

	pagefault_disable();
	ret = raw_copy_from_user_allowed(dst, src, size);
	pagefault_enable();

	return ret ? -EFAULT : 0;
}

static __always_inline long
probe_write_common(void __user *dst, const void *src, size_t size)
{
	long ret;

	pagefault_disable();
	ret = raw_copy_to_user_allowed(dst, src, size);
	pagefault_enable();

	return ret ? -EFAULT : 0;
}

long probe_kernel_read(void *dst, const void *src, size_t size)
{
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	ret = probe_read_common(dst, (__force const void __user *)src, size);
	set_fs(old_fs);

	return ret;
}

long probe_kernel_write(void *dst, const void *src, size_t size)
{
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	ret = probe_write_common((__force void __user *)dst, src, size);
	set_fs(old_fs);

	return ret;
}
