// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Vivo Communication Technology Co. Ltd.
 * Copyright (C) 2020 Wang Wenhu <wenhu.wang@vivo.com>
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#include "sram_uapi.h"

#define DRIVER_NAME	"sram_uapi"

struct sram_resource {
	struct list_head	list;
	struct res_info		info;
	phys_addr_t		phys;
	void			*virt;
	struct vm_area_struct	*vma;
	struct sram_uapi	*parent;
};

struct sram_uapi {
	struct list_head	res_list;
	struct sram_api		*sa;
};

static DEFINE_MUTEX(sram_list_lock);
static LIST_HEAD(sram_list);

long sram_api_register(struct sram_api *sa)
{
	struct sram_api *cur;

	if (!sa || !sa->name || !sa->sram_alloc || !sa->sram_free)
		return -EINVAL;

	mutex_lock(&sram_list_lock);
	list_for_each_entry(cur, &sram_list, list) {
		if (cur->type == sa->type) {
			pr_err("error sram %s type %d exists\n", sa->name,
			       sa->type);
			mutex_unlock(&sram_list_lock);
			return -EEXIST;
		}
	}

	kref_init(&sa->kref);
	list_add_tail(&sa->list, &sram_list);
	pr_info("sram %s type %d registered\n", sa->name, sa->type);

	mutex_unlock(&sram_list_lock);

	return 0;
};
EXPORT_SYMBOL(sram_api_register);

long sram_api_unregister(struct sram_api *sa)
{
	struct sram_api *cur, *tmp;
	long ret = -ENODEV;

	if (!sa || !sa->name || !sa->sram_alloc || !sa->sram_free)
		return -EINVAL;

	mutex_lock(&sram_list_lock);
	list_for_each_entry_safe(cur, tmp, &sram_list, list) {
		if (cur->type == sa->type && !strcmp(cur->name, sa->name)) {
			if (kref_read(&cur->kref)) {
				pr_err("error sram %s type %d is busy\n",
					sa->name, sa->type);
				ret = -EBUSY;
			} else {
				list_del(&cur->list);
				pr_info("sram %s type %d unregistered\n",
					sa->name, sa->type);
				ret = 0;
			}
			break;
		}
	}
	mutex_unlock(&sram_list_lock);

	return ret;
};
EXPORT_SYMBOL(sram_api_unregister);

static struct sram_api *get_sram_api_from_type(__u32 type)
{
	struct sram_api *cur;

	mutex_lock(&sram_list_lock);
	list_for_each_entry(cur, &sram_list, list) {
		if (cur->type == type) {
			kref_get(&cur->kref);
			mutex_unlock(&sram_list_lock);
			return cur;
		}
	}
	mutex_unlock(&sram_list_lock);

	return NULL;
}

static void sram_uapi_res_insert(struct sram_uapi *uapi,
				 struct sram_resource *res)
{
	struct sram_resource *cur, *tmp;
	struct list_head *head = &uapi->res_list;

	list_for_each_entry_safe(cur, tmp, head, list) {
		if (&tmp->list != head &&
		    (cur->info.offset + cur->info.size + res->info.size <=
		    tmp->info.offset)) {
			res->info.offset = cur->info.offset + cur->info.size;
			res->parent = uapi;
			list_add(&res->list, &cur->list);
			return;
		}
	}

	if (list_empty(head))
		res->info.offset = 0;
	else {
		tmp = list_last_entry(head, struct sram_resource, list);
		res->info.offset = tmp->info.offset + tmp->info.size;
	}
	list_add_tail(&res->list, head);
}

static struct sram_resource *sram_uapi_res_delete(struct sram_uapi *uapi,
						  struct res_info *info)
{
	struct sram_resource *res, *tmp;

	list_for_each_entry_safe(res, tmp, &uapi->res_list, list) {
		if (res->info.offset == info->offset) {
			list_del(&res->list);
			res->parent = NULL;
			return res;
		}
	}

	return NULL;
}

static struct sram_resource *sram_uapi_find_res(struct sram_uapi *uapi,
						__u32 offset)
{
	struct sram_resource *res;

	list_for_each_entry(res, &uapi->res_list, list) {
		if (res->info.offset == offset)
			return res;
	}

	return NULL;
}

static int sram_uapi_open(struct inode *inode, struct file *filp)
{
	struct sram_uapi *uapi;

	uapi = kzalloc(sizeof(*uapi), GFP_KERNEL);
	if (!uapi)
		return -ENOMEM;

	INIT_LIST_HEAD(&uapi->res_list);
	filp->private_data = uapi;

	return 0;
}

static long sram_uapi_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	struct sram_uapi *uapi = filp->private_data;
	struct sram_resource *res;
	struct res_info info;
	long ret = -ENOIOCTLCMD;
	int size;
	__u32 type;

	if (!uapi)
		return ret;

	switch (cmd) {
	case SRAM_UAPI_IOC_SET_SRAM_TYPE:
		if (uapi->sa)
			return -EEXIST;

		get_user(type, (const __u32 __user *)arg);
		uapi->sa = get_sram_api_from_type(type);
		if (uapi->sa)
			ret = 0;
		else
			ret = -ENODEV;

		break;

	case SRAM_UAPI_IOC_ALLOC:
		if (!uapi->sa)
			return -EINVAL;

		res = kzalloc(sizeof(*res), GFP_KERNEL);
		if (!res)
			return -ENOMEM;

		size = copy_from_user((void *)&res->info,
				      (const void __user *)arg,
				      sizeof(res->info));
		if (!PAGE_ALIGNED(res->info.size) || !res->info.size)
			return -EINVAL;

		res->virt = (void *)uapi->sa->sram_alloc(res->info.size,
							 &res->phys,
							 res->info.size);
		if (!res->virt) {
			kfree(res);
			return -ENOMEM;
		}

		sram_uapi_res_insert(uapi, res);
		size = copy_to_user((void __user *)arg,
				    (const void *)&res->info,
				    sizeof(res->info));

		ret = 0;
		break;

	case SRAM_UAPI_IOC_FREE:
		if (!uapi->sa)
			return -EINVAL;

		size = copy_from_user((void *)&info, (const void __user *)arg,
				      sizeof(info));

		res = sram_uapi_res_delete(uapi, &info);
		if (!res) {
			pr_err("error no sram resource found\n");
			return -EINVAL;
		}

		uapi->sa->sram_free(res->virt);
		kfree(res);

		ret = 0;
		break;

	default:
		pr_err("error no cmd not supported\n");
		break;
	}

	return ret;
}

static int sram_uapi_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct sram_uapi *uapi = filp->private_data;
	struct sram_resource *res;

	res = sram_uapi_find_res(uapi, vma->vm_pgoff);
	if (!res)
		return -EINVAL;

	if (vma->vm_end - vma->vm_start > res->info.size)
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start,
				res->phys >> PAGE_SHIFT,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot);
}

static void sram_uapi_res_release(struct sram_uapi *uapi)
{
	struct sram_resource *res, *tmp;

	list_for_each_entry_safe(res, tmp, &uapi->res_list, list) {
		list_del(&res->list);
		uapi->sa->sram_free(res->virt);
		kfree(res);
	}
}

static int sram_uapi_release(struct inode *inodp, struct file *filp)
{
	struct sram_uapi *uapi = filp->private_data;

	sram_uapi_res_release(uapi);
	if (uapi->sa)
		kref_put(&uapi->sa->kref, NULL);

	kfree(uapi);

	return 0;
}

static const struct file_operations sram_uapi_ops = {
	.owner		= THIS_MODULE,
	.open		= sram_uapi_open,
	.unlocked_ioctl = sram_uapi_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.mmap		= sram_uapi_mmap,
	.release	= sram_uapi_release,
};

static struct miscdevice sram_uapi_miscdev = {
	MISC_DYNAMIC_MINOR,
	"sram",
	&sram_uapi_ops,
};

static int __init sram_uapi_init(void)
{
	int ret;

	INIT_LIST_HEAD(&sram_list);
	mutex_init(&sram_list_lock);

	ret = misc_register(&sram_uapi_miscdev);
	if (ret)
		pr_err("failed to register sram uapi misc device\n");

	return ret;
}

static void __exit sram_uapi_exit(void)
{
	misc_deregister(&sram_uapi_miscdev);
}

module_init(sram_uapi_init);
module_exit(sram_uapi_exit);

MODULE_AUTHOR("Wang Wenhu <wenhu.wang@vivo.com>");
MODULE_DESCRIPTION("SRAM User API Driver");
MODULE_ALIAS("platform:" DRIVER_NAME);
MODULE_LICENSE("GPL v2");
