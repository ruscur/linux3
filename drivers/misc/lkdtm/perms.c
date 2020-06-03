// SPDX-License-Identifier: GPL-2.0
/*
 * This is for all the tests related to validating kernel memory
 * permissions: non-executable regions, non-writable regions, and
 * even non-readable regions.
 */
#include "lkdtm.h"
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <asm/cacheflush.h>

/* Whether or not to fill the target memory area with do_nothing(). */
#define CODE_WRITE	true
#define CODE_AS_IS	false

/* How many bytes to copy to be sure we've copied enough of do_nothing(). */
#define EXEC_SIZE 64

/* This is non-const, so it will end up in the .data section. */
static u8 data_area[EXEC_SIZE];

/* This is cost, so it will end up in the .rodata section. */
static const unsigned long rodata = 0xAA55AA55;

/* This is marked __ro_after_init, so it should ultimately be .rodata. */
static unsigned long ro_after_init __ro_after_init = 0x55AA5500;

/*
 * This just returns to the caller. It is designed to be copied into
 * non-executable memory regions.
 */
static void do_nothing(void)
{
	return;
}

/* Must immediately follow do_nothing for size calculuations to work out. */
static void do_overwritten(void)
{
	pr_info("do_overwritten wasn't overwritten!\n");
	return;
}

static noinline void execute_location(void *dst, bool write)
{
	void (*func)(void) = dst;

	pr_info("attempting ok execution at %px\n", do_nothing);
	do_nothing();

	if (write == CODE_WRITE) {
		memcpy(dst, do_nothing, EXEC_SIZE);
		flush_icache_range((unsigned long)dst,
				   (unsigned long)dst + EXEC_SIZE);
	}
	pr_info("attempting bad execution at %px\n", func);
	func();
}

static void execute_user_location(void *dst)
{
	int copied;

	/* Intentionally crossing kernel/user memory boundary. */
	void (*func)(void) = dst;

	pr_info("attempting ok execution at %px\n", do_nothing);
	do_nothing();

	copied = access_process_vm(current, (unsigned long)dst, do_nothing,
				   EXEC_SIZE, FOLL_WRITE);
	if (copied < EXEC_SIZE)
		return;
	pr_info("attempting bad execution at %px\n", func);
	func();
}

void lkdtm_WRITE_RO(void)
{
	/* Explicitly cast away "const" for the test. */
	unsigned long *ptr = (unsigned long *)&rodata;

	pr_info("attempting bad rodata write at %px\n", ptr);
	*ptr ^= 0xabcd1234;
}

void lkdtm_WRITE_RO_AFTER_INIT(void)
{
	unsigned long *ptr = &ro_after_init;

	/*
	 * Verify we were written to during init. Since an Oops
	 * is considered a "success", a failure is to just skip the
	 * real test.
	 */
	if ((*ptr & 0xAA) != 0xAA) {
		pr_info("%p was NOT written during init!?\n", ptr);
		return;
	}

	pr_info("attempting bad ro_after_init write at %px\n", ptr);
	*ptr ^= 0xabcd1234;
}

void lkdtm_WRITE_KERN(void)
{
	size_t size;
	unsigned char *ptr;

	size = (unsigned long)do_overwritten - (unsigned long)do_nothing;
	ptr = (unsigned char *)do_overwritten;

	pr_info("attempting bad %zu byte write at %px\n", size, ptr);
	memcpy(ptr, (unsigned char *)do_nothing, size);
	flush_icache_range((unsigned long)ptr, (unsigned long)(ptr + size));

	do_overwritten();
}

void lkdtm_EXEC_DATA(void)
{
	execute_location(data_area, CODE_WRITE);
}

void lkdtm_EXEC_STACK(void)
{
	u8 stack_area[EXEC_SIZE];
	execute_location(stack_area, CODE_WRITE);
}

void lkdtm_EXEC_KMALLOC(void)
{
	u32 *kmalloc_area = kmalloc(EXEC_SIZE, GFP_KERNEL);
	execute_location(kmalloc_area, CODE_WRITE);
	kfree(kmalloc_area);
}

void lkdtm_EXEC_VMALLOC(void)
{
	u32 *vmalloc_area = vmalloc(EXEC_SIZE);
	execute_location(vmalloc_area, CODE_WRITE);
	vfree(vmalloc_area);
}

void lkdtm_EXEC_RODATA(void)
{
	execute_location(lkdtm_rodata_do_nothing, CODE_AS_IS);
}

void lkdtm_EXEC_USERSPACE(void)
{
	unsigned long user_addr;

	user_addr = vm_mmap(NULL, 0, PAGE_SIZE,
			    PROT_READ | PROT_WRITE | PROT_EXEC,
			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
	if (user_addr >= TASK_SIZE) {
		pr_warn("Failed to allocate user memory\n");
		return;
	}
	execute_user_location((void *)user_addr);
	vm_munmap(user_addr, PAGE_SIZE);
}

void lkdtm_EXEC_NULL(void)
{
	execute_location(NULL, CODE_AS_IS);
}

void lkdtm_ACCESS_USERSPACE(void)
{
	unsigned long user_addr, tmp = 0;
	unsigned long *ptr;

	user_addr = vm_mmap(NULL, 0, PAGE_SIZE,
			    PROT_READ | PROT_WRITE | PROT_EXEC,
			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
	if (user_addr >= TASK_SIZE) {
		pr_warn("Failed to allocate user memory\n");
		return;
	}

	if (copy_to_user((void __user *)user_addr, &tmp, sizeof(tmp))) {
		pr_warn("copy_to_user failed\n");
		vm_munmap(user_addr, PAGE_SIZE);
		return;
	}

	ptr = (unsigned long *)user_addr;

	pr_info("attempting bad read at %px\n", ptr);
	tmp = *ptr;
	tmp += 0xc0dec0de;

	pr_info("attempting bad write at %px\n", ptr);
	*ptr = tmp;

	vm_munmap(user_addr, PAGE_SIZE);
}

void lkdtm_ACCESS_NULL(void)
{
	unsigned long tmp;
	unsigned long *ptr = (unsigned long *)NULL;

	pr_info("attempting bad read at %px\n", ptr);
	tmp = *ptr;
	tmp += 0xc0dec0de;

	pr_info("attempting bad write at %px\n", ptr);
	*ptr = tmp;
}

#if defined(CONFIG_PPC) && defined(CONFIG_STRICT_KERNEL_RWX)
#include <include/asm/code-patching.h>

extern unsigned long read_cpu_patching_addr(unsigned int cpu);

static struct ppc_inst * const patch_site = (struct ppc_inst *)&do_nothing;

static int lkdtm_patching_cpu(void *data)
{
	int err = 0;
	struct ppc_inst insn = ppc_inst(0xdeadbeef);

	pr_info("starting patching_cpu=%d\n", smp_processor_id());
	do {
		err = patch_instruction(patch_site, insn);
	} while (ppc_inst_equal(ppc_inst_read(READ_ONCE(patch_site)), insn) &&
			!err && !kthread_should_stop());

	if (err)
		pr_warn("patch_instruction returned error: %d\n", err);

	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}

	return err;
}

void lkdtm_HIJACK_PATCH(void)
{
	struct task_struct *patching_kthrd;
	struct ppc_inst original_insn;
	int patching_cpu, hijacker_cpu, attempts;
	unsigned long addr;
	bool hijacked;

	if (num_online_cpus() < 2) {
		pr_warn("need at least two cpus\n");
		return;
	}

	original_insn = ppc_inst_read(READ_ONCE(patch_site));

	hijacker_cpu = smp_processor_id();
	patching_cpu = cpumask_any_but(cpu_online_mask, hijacker_cpu);

	patching_kthrd = kthread_create_on_node(&lkdtm_patching_cpu, NULL,
						cpu_to_node(patching_cpu),
						"lkdtm_patching_cpu");
	kthread_bind(patching_kthrd, patching_cpu);
	wake_up_process(patching_kthrd);

	addr = offset_in_page(patch_site) | read_cpu_patching_addr(patching_cpu);

	pr_info("starting hijacker_cpu=%d\n", hijacker_cpu);
	for (attempts = 0; attempts < 100000; ++attempts) {
		/* Use __put_user to catch faults without an Oops */
		hijacked = !__put_user(0xbad00bad, (unsigned int *)addr);

		if (hijacked) {
			if (kthread_stop(patching_kthrd))
				goto out;
			break;
		}
	}
	pr_info("hijack attempts: %d\n", attempts);

	if (hijacked) {
		if (*(unsigned int *)READ_ONCE(patch_site) == 0xbad00bad)
			pr_err("overwrote kernel text\n");
		/*
		 * There are window conditions where the hijacker cpu manages to
		 * write to the patch site but the site gets overwritten again by
		 * the patching cpu. We still consider that a "successful" hijack
		 * since the hijacker cpu did not fault on the write.
		 */
		pr_err("FAIL: wrote to another cpu's patching area\n");
	} else {
		kthread_stop(patching_kthrd);
	}

out:
	/* Restore the original insn for any future lkdtm tests */
	patch_instruction(patch_site, original_insn);
}

#else

void lkdtm_HIJACK_PATCH(void)
{
	if (!IS_ENABLED(CONFIG_PPC))
		pr_err("XFAIL: this test is powerpc-only\n");
	if (!IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
		pr_err("XFAIL: this test requires CONFIG_STRICT_KERNEL_RWX\n");
}

#endif /* CONFIG_PPC && CONFIG_STRICT_KERNEL_RWX */

void __init lkdtm_perms_init(void)
{
	/* Make sure we can write to __ro_after_init values during __init */
	ro_after_init |= 0xAA;

}
