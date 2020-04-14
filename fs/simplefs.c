/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/simplefs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fsnotify.h>

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

struct inode *simple_alloc_anon_inode(struct simple_fs *fs)
{
	return alloc_anon_inode(fs->mount->mnt_sb);
}
EXPORT_SYMBOL(simple_alloc_anon_inode);

static struct dentry *failed_creating(struct simple_fs *fs, struct dentry *dentry)
{
	inode_unlock(d_inode(dentry->d_parent));
	dput(dentry);
	simple_release_fs(fs);
	return ERR_PTR(-ENOMEM);
}

struct dentry *simplefs_create_dentry(struct simple_fs *fs, struct file_system_type *type,
				      const char *name, struct dentry *parent,
				      struct inode **inode)
{
	struct dentry *dentry;
	int error;

	pr_debug("creating file '%s'\n", name);

	if (IS_ERR(parent))
		return parent;

	error = simple_pin_fs(fs, type);
	if (error) {
		pr_err("Unable to pin filesystem for file '%s'\n", name);
		return ERR_PTR(error);
	}

	/* If the parent is not specified, we create it in the root.
	 * We need the root dentry to do this, which is in the super
	 * block. A pointer to that is in the struct vfsmount that we
	 * have around.
	 */
	if (!parent)
		parent = fs->mount->mnt_root;

	inode_lock(d_inode(parent));
	dentry = lookup_one_len(name, parent, strlen(name));
	if (!IS_ERR(dentry) && d_really_is_positive(dentry)) {
		if (d_is_dir(dentry))
			pr_err("Directory '%s' with parent '%s' already present!\n",
			       name, parent->d_name.name);
		else
			pr_err("File '%s' in directory '%s' already present!\n",
			       name, parent->d_name.name);
		dput(dentry);
		dentry = ERR_PTR(-EEXIST);
	}

	if (IS_ERR(dentry)) {
		inode_unlock(d_inode(parent));
		simple_release_fs(fs);
	}


	if (IS_ERR(dentry))
		return dentry;

	*inode = simple_new_inode(fs->mount->mnt_sb);
	if (unlikely(!(*inode))) {
		pr_err("out of free inodes, can not create file '%s'\n",
		       name);
		return failed_creating(fs, dentry);
	}

	return dentry;
}
EXPORT_SYMBOL(simplefs_create_dentry);

struct dentry *simplefs_create_file(struct simple_fs *fs, struct file_system_type *type,
				    const char *name, umode_t mode,
				    struct dentry *parent, void *data,
				    struct inode **inode)
{
	struct dentry *dentry;

	WARN_ON((mode & S_IFMT) && !S_ISREG(mode));
	mode |= S_IFREG;

	dentry = simplefs_create_dentry(fs, type, name, parent, inode);

	if (IS_ERR(dentry))
		return dentry;

	(*inode)->i_mode = mode;
	(*inode)->i_private = data;

	return dentry;
}
EXPORT_SYMBOL(simplefs_create_file);

struct dentry *simplefs_finish_dentry(struct dentry *dentry, struct inode *inode)
{
	d_instantiate(dentry, inode);
	if (S_ISDIR(inode->i_mode)) {
		inc_nlink(d_inode(dentry->d_parent));
		fsnotify_mkdir(d_inode(dentry->d_parent), dentry);
	} else {
		fsnotify_create(d_inode(dentry->d_parent), dentry);
	}
	inode_unlock(d_inode(dentry->d_parent));
	return dentry;
}
EXPORT_SYMBOL(simplefs_finish_dentry);

struct dentry *simplefs_create_dir(struct simple_fs *fs, struct file_system_type *type,
				   const char *name, umode_t mode, struct dentry *parent,
				   struct inode **inode)
{
	struct dentry *dentry;

	WARN_ON((mode & S_IFMT) && !S_ISDIR(mode));
	mode |= S_IFDIR;

	dentry = simplefs_create_dentry(fs, type, name, parent, inode);
	if (IS_ERR(dentry))
		return dentry;

	(*inode)->i_mode = mode;
	(*inode)->i_op = &simple_dir_inode_operations;
	(*inode)->i_fop = &simple_dir_operations;

	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	inc_nlink(*inode);
	return dentry;
}
EXPORT_SYMBOL(simplefs_create_dir);

struct dentry *simplefs_create_symlink(struct simple_fs *fs, struct file_system_type *type,
				       const char *name, struct dentry *parent,
				       const char *target, struct inode **inode)
{
	struct dentry *dentry;
	char *link = kstrdup(target, GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

	dentry = simplefs_create_dentry(fs, type, name, parent, inode);
	if (IS_ERR(dentry)) {
		kfree_link(link);
		return dentry;
	}

	(*inode)->i_mode = S_IFLNK | S_IRWXUGO;
	(*inode)->i_link = link;
	(*inode)->i_op = &simple_symlink_inode_operations;
	return dentry;
}
EXPORT_SYMBOL(simplefs_create_symlink);
