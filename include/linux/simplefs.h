/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SIMPLEFS_H
#define _LINUX_SIMPLEFS_H

#include <linux/fs.h>

extern int simple_pin_fs(struct file_system_type *, struct vfsmount **mount, int *count);
extern void simple_release_fs(struct vfsmount **mount, int *count);

#endif
