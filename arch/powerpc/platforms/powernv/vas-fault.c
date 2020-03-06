// SPDX-License-Identifier: GPL-2.0+
/*
 * VAS Fault handling.
 * Copyright 2019, IBM Corporation
 */

#define pr_fmt(fmt) "vas: " fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/mmu_context.h>
#include <asm/icswx.h>

#include "vas.h"

/*
 * The maximum FIFO size for fault window can be 8MB
 * (VAS_RX_FIFO_SIZE_MAX). Using 4MB FIFO since each VAS
 * instance will be having fault window.
 * 8MB FIFO can be used if expects more faults for each VAS
 * instance.
 */
#define VAS_FAULT_WIN_FIFO_SIZE	(4 << 20)

/*
 * Update the CSB to indicate a translation error.
 *
 * If we are unable to update the CSB means copy_to_user failed due to
 * invalid csb_addr, send a signal to the process.
 *
 * Remaining settings in the CSB are based on wait_for_csb() of
 * NX-GZIP.
 */
static void update_csb(struct vas_window *window,
			struct coprocessor_request_block *crb)
{
	int rc;
	struct pid *pid;
	void __user *csb_addr;
	struct task_struct *tsk;
	struct kernel_siginfo info;
	struct coprocessor_status_block csb;

	/*
	 * NX user space windows can not be opened for task->mm=NULL
	 * and faults will not be generated for kernel requests.
	 */
	if (!window->mm || !window->user_win)
		return;

	csb_addr = (void __user *)be64_to_cpu(crb->csb_addr);

	csb.cc = CSB_CC_TRANSLATION;
	csb.ce = CSB_CE_TERMINATION;
	csb.cs = 0;
	csb.count = 0;

	/*
	 * NX operates and returns in BE format as defined CRB struct.
	 * So return fault_storage_addr in BE as NX pastes in FIFO and
	 * expects user space to convert to CPU format.
	 */
	csb.address = crb->stamp.nx.fault_storage_addr;
	csb.flags = 0;

	pid = window->pid;
	tsk = get_pid_task(pid, PIDTYPE_PID);
	/*
	 * Send window will be closed after processing all NX requests
	 * and process exits after closing all windows. In multi-thread
	 * applications, thread may not exists, but does not close FD
	 * (means send window) upon exit. Parent thread (tgid) can use
	 * and close the window later.
	 * pid and mm references are taken when window is opened by
	 * process (pid). So tgid is used only when child thread opens
	 * a window and exits without closing it in multithread tasks.
	 */
	if (!tsk) {
		pid = window->tgid;
		tsk = get_pid_task(pid, PIDTYPE_PID);
		/*
		 * Parent thread will be closing window during its exit.
		 * So should not get here.
		 */
		if (!tsk)
			return;
	}

	/* Return if the task is exiting. */
	if (tsk->flags & PF_EXITING) {
		put_task_struct(tsk);
		return;
	}

	use_mm(window->mm);
	rc = copy_to_user(csb_addr, &csb, sizeof(csb));
	/*
	 * User space polls on csb.flags (first byte). So add barrier
	 * then copy first byte with csb flags update.
	 */
	smp_mb();
	if (!rc) {
		csb.flags = CSB_V;
		rc = copy_to_user(csb_addr, &csb, sizeof(u8));
	}
	unuse_mm(window->mm);
	put_task_struct(tsk);

	/* Success */
	if (!rc)
		return;

	pr_debug("Invalid CSB address 0x%p signalling pid(%d)\n",
			csb_addr, pid_vnr(pid));

	clear_siginfo(&info);
	info.si_signo = SIGSEGV;
	info.si_errno = EFAULT;
	info.si_code = SEGV_MAPERR;
	info.si_addr = csb_addr;

	/*
	 * process will be polling on csb.flags after request is sent to
	 * NX. So generally CSB update should not fail except when an
	 * application does not follow the process properly. So an error
	 * message will be displayed and leave it to user space whether
	 * to ignore or handle this signal.
	 */
	rcu_read_lock();
	rc = kill_pid_info(SIGSEGV, &info, pid);
	rcu_read_unlock();

	pr_devel("%s(): pid %d kill_proc_info() rc %d\n", __func__,
			pid_vnr(pid), rc);
}

/*
 * Process valid CRBs in fault FIFO.
 */
irqreturn_t vas_fault_thread_fn(int irq, void *data)
{
	struct vas_instance *vinst = data;
	struct coprocessor_request_block *crb, *entry;
	struct coprocessor_request_block buf;
	struct vas_window *window;
	unsigned long flags;
	void *fifo;

	crb = &buf;

	/*
	 * VAS can interrupt with multiple page faults. So process all
	 * valid CRBs within fault FIFO until reaches invalid CRB.
	 * NX updates nx_fault_stamp in CRB and pastes in fault FIFO.
	 * kernel retrives send window from parition send window ID
	 * (pswid) in nx_fault_stamp. So pswid should be valid and
	 * ccw[0] (in be) should be zero since this bit is reserved.
	 * If user space touches this bit, NX returns with "CRB format
	 * error".
	 *
	 * After reading CRB entry, invalidate it with pswid (set
	 * 0xffffffff) and ccw[0] (set to 1).
	 *
	 * In case kernel receives another interrupt with different page
	 * fault, CRBs are already processed by the previous handling. So
	 * will be returned from this function when it sees invalid CRB.
	 */
	do {
		mutex_lock(&vinst->mutex);

		spin_lock_irqsave(&vinst->fault_lock, flags);
		/*
		 * Advance the fault fifo pointer to next CRB.
		 * Use CRB_SIZE rather than sizeof(*crb) since the latter is
		 * aligned to CRB_ALIGN (256) but the CRB written to by VAS is
		 * only CRB_SIZE in len.
		 */
		fifo = vinst->fault_fifo + (vinst->fault_crbs * CRB_SIZE);
		entry = fifo;

		if ((entry->stamp.nx.pswid == cpu_to_be32(FIFO_INVALID_ENTRY))
			|| (entry->ccw & cpu_to_be32(CCW0_INVALID))) {
			atomic_set(&vinst->faults_in_progress, 0);
			spin_unlock_irqrestore(&vinst->fault_lock, flags);
			mutex_unlock(&vinst->mutex);
			return IRQ_HANDLED;
		}

		spin_unlock_irqrestore(&vinst->fault_lock, flags);
		vinst->fault_crbs++;
		if (vinst->fault_crbs == (vinst->fault_fifo_size / CRB_SIZE))
			vinst->fault_crbs = 0;

		memcpy(crb, fifo, CRB_SIZE);
		entry->stamp.nx.pswid = cpu_to_be32(FIFO_INVALID_ENTRY);
		entry->ccw |= cpu_to_be32(CCW0_INVALID);
		mutex_unlock(&vinst->mutex);

		pr_devel("VAS[%d] fault_fifo %p, fifo %p, fault_crbs %d\n",
				vinst->vas_id, vinst->fault_fifo, fifo,
				vinst->fault_crbs);

		window = vas_pswid_to_window(vinst,
				be32_to_cpu(crb->stamp.nx.pswid));

		if (IS_ERR(window)) {
			/*
			 * We got an interrupt about a specific send
			 * window but we can't find that window and we can't
			 * even clean it up (return credit).
			 * But we should not get here.
			 */
			pr_err("VAS[%d] fault_fifo %p, fifo %p, pswid 0x%x, fault_crbs %d bad CRB?\n",
				vinst->vas_id, vinst->fault_fifo, fifo,
				be32_to_cpu(crb->stamp.nx.pswid),
				vinst->fault_crbs);

			WARN_ON_ONCE(1);
			atomic_set(&vinst->faults_in_progress, 0);
			return IRQ_HANDLED;
		}

		update_csb(window, crb);
	} while (true);
}

/*
 * Fault window is opened per VAS instance. NX pastes fault CRB in fault
 * FIFO upon page faults.
 */
int vas_setup_fault_window(struct vas_instance *vinst)
{
	struct vas_rx_win_attr attr;

	vinst->fault_fifo_size = VAS_FAULT_WIN_FIFO_SIZE;
	vinst->fault_fifo = kzalloc(vinst->fault_fifo_size, GFP_KERNEL);
	if (!vinst->fault_fifo) {
		pr_err("Unable to alloc %d bytes for fault_fifo\n",
				vinst->fault_fifo_size);
		return -ENOMEM;
	}

	/*
	 * Invalidate all CRB entries. NX pastes valid entry for each fault.
	 */
	memset(vinst->fault_fifo, FIFO_INVALID_ENTRY, vinst->fault_fifo_size);
	vas_init_rx_win_attr(&attr, VAS_COP_TYPE_FAULT);

	attr.rx_fifo_size = vinst->fault_fifo_size;
	attr.rx_fifo = vinst->fault_fifo;

	/*
	 * Max creds is based on number of CRBs can fit in the FIFO.
	 * (fault_fifo_size/CRB_SIZE). If 8MB FIFO is used, max creds
	 * will be 0xffff since the receive creds field is 16bits wide.
	 */
	attr.wcreds_max = vinst->fault_fifo_size / CRB_SIZE;
	attr.lnotify_lpid = 0;
	attr.lnotify_pid = mfspr(SPRN_PID);
	attr.lnotify_tid = mfspr(SPRN_PID);

	vinst->fault_win = vas_rx_win_open(vinst->vas_id, VAS_COP_TYPE_FAULT,
					&attr);

	if (IS_ERR(vinst->fault_win)) {
		pr_err("VAS: Error %ld opening FaultWin\n",
			PTR_ERR(vinst->fault_win));
		kfree(vinst->fault_fifo);
		return PTR_ERR(vinst->fault_win);
	}

	pr_devel("VAS: Created FaultWin %d, LPID/PID/TID [%d/%d/%d]\n",
			vinst->fault_win->winid, attr.lnotify_lpid,
			attr.lnotify_pid, attr.lnotify_tid);

	return 0;
}
