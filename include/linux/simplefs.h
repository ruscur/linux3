/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SIMPLEFS_H
#define _LINUX_SIMPLEFS_H

#include <linux/fs.h>

struct simple_fs {
	struct vfsmount *mount;
	int count;
};

extern int simple_pin_fs(struct simple_fs *, struct file_system_type *);
extern void simple_release_fs(struct simple_fs *);

extern struct inode *simple_alloc_anon_inode(struct simple_fs *fs);

#endif
