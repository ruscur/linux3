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

extern struct dentry *simplefs_create_dentry(struct simple_fs *fs,
					     struct file_system_type *type,
					     const char *name, struct dentry *parent,
					     struct inode **inode);
struct dentry *simplefs_finish_dentry(struct dentry *dentry, struct inode *inode);

extern struct dentry *simplefs_create_file(struct simple_fs *fs,
					   struct file_system_type *type,
					   const char *name, umode_t mode,
					   struct dentry *parent, void *data,
					   struct inode **inode);
extern struct dentry *simplefs_create_dir(struct simple_fs *fs, struct file_system_type *type,
					  const char *name, umode_t mode, struct dentry *parent,
					  struct inode **inode);
extern struct dentry *simplefs_create_symlink(struct simple_fs *fs, struct file_system_type *type,
					      const char *name, struct dentry *parent,
					      const char *target, struct inode **inode);


#endif
