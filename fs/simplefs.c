/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/simplefs.h>
#include <linux/mount.h>

static DEFINE_SPINLOCK(pin_fs_lock);

int simple_pin_fs(struct simple_fs *fs, struct file_system_type *type)
{
	struct vfsmount *mnt = NULL;
	spin_lock(&pin_fs_lock);
	if (unlikely(!fs->mount)) {
		spin_unlock(&pin_fs_lock);
		mnt = vfs_kern_mount(type, SB_KERNMOUNT, type->name, NULL);
		if (IS_ERR(mnt))
			return PTR_ERR(mnt);
		spin_lock(&pin_fs_lock);
		if (!fs->mount)
			fs->mount = mnt;
	}
	mntget(fs->mount);
	++fs->count;
	spin_unlock(&pin_fs_lock);
	mntput(mnt);
	return 0;
}
EXPORT_SYMBOL(simple_pin_fs);

void simple_release_fs(struct simple_fs *fs)
{
	struct vfsmount *mnt;
	spin_lock(&pin_fs_lock);
	mnt = fs->mount;
	if (!--fs->count)
		fs->mount = NULL;
	spin_unlock(&pin_fs_lock);
	mntput(mnt);
}
EXPORT_SYMBOL(simple_release_fs);
