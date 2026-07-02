// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/vfio_pci_core.h>

#define NVGRACE_EGM_DEV_NAME "egm"
#define MAX_EGM_NODES 4

static dev_t dev;
static struct class *class;

struct gpu_node {
	struct list_head list;
	struct pci_dev *pdev;
};

struct nvgrace_egm_dev {
	struct device device;
	struct cdev cdev;
	phys_addr_t egmphys;
	size_t egmlength;
	u64 egmpxm;
	struct list_head gpus;
};

struct nvgrace_egm_dev_entry {
	struct list_head list;
	struct nvgrace_egm_dev *egm_dev;
};

/*
 * Track egm device lists. Note that there is one device per socket.
 * All the GPUs belonging to the same sockets are associated with
 * the EGM device for that socket.
 */
static LIST_HEAD(egm_chardevs);

static int nvgrace_egm_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int nvgrace_egm_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int nvgrace_egm_mmap(struct file *file, struct vm_area_struct *vma)
{
	/*
	 * Mapping the EGM region into userspace is implemented by a later
	 * patch. Until then refuse the mmap.
	 */
	return -EOPNOTSUPP;
}

static const struct file_operations file_ops = {
	.owner = THIS_MODULE,
	.open = nvgrace_egm_open,
	.release = nvgrace_egm_release,
	.mmap = nvgrace_egm_mmap,
};

static int nvgrace_egm_create_gpu_links(struct nvgrace_egm_dev *egm_dev,
					struct pci_dev *pdev)
{
	int ret;

	ret = sysfs_create_link(&egm_dev->device.kobj,
				&pdev->dev.kobj,
				dev_name(&pdev->dev));

	if (ret && ret != -EEXIST)
		return ret;

	return 0;
}

static void remove_egm_symlinks(struct nvgrace_egm_dev *egm_dev,
				struct pci_dev *pdev)
{
	sysfs_remove_link(&egm_dev->device.kobj, dev_name(&pdev->dev));
}

static int add_gpu(struct nvgrace_egm_dev *egm_dev, struct pci_dev *pdev)
{
	struct gpu_node *node;

	node = kzalloc_obj(*node, GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	/*
	 * The pdev is stored for the lifetime of the EGM device but it is
	 * obtained from a for_each_pci_dev() walk that drops its reference as
	 * it advances. Take a reference here so the stored pointer stays valid
	 * even if the GPU is later unbound; remove_gpus() drops it.
	 */
	node->pdev = pci_dev_get(pdev);

	list_add_tail(&node->list, &egm_dev->gpus);

	return nvgrace_egm_create_gpu_links(egm_dev, pdev);
}

static void remove_gpus(struct nvgrace_egm_dev *egm_dev)
{
	struct gpu_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &egm_dev->gpus, list) {
		remove_egm_symlinks(egm_dev, node->pdev);
		list_del(&node->list);
		pci_dev_put(node->pdev);
		kfree(node);
	}
}

static void egm_chardev_release(struct device *dev)
{
	struct nvgrace_egm_dev *egm_chardev = container_of(dev, struct nvgrace_egm_dev, device);

	remove_gpus(egm_chardev);
	kfree(egm_chardev);
}

static struct nvgrace_egm_dev *setup_egm_chardev(u64 egmphys, u64 egmlength,
						 u64 egmpxm)
{
	struct nvgrace_egm_dev *egm_chardev;
	unsigned int baseminor = MINOR(dev);
	int ret;

	/*
	 * Only MAX_EGM_NODES minors from baseminor were reserved. Reject a PXM
	 * outside that window.
	 */
	if (egmpxm < baseminor || egmpxm - baseminor >= MAX_EGM_NODES) {
		pr_err("nvgrace-egm: EGM proximity domain %llu outside reserved minor window [%u, %u)\n",
		       egmpxm, baseminor, baseminor + MAX_EGM_NODES);
		goto create_err;
	}

	egm_chardev = kzalloc_obj(*egm_chardev, GFP_KERNEL);
	if (!egm_chardev)
		goto create_err;

	device_initialize(&egm_chardev->device);

	/*
	 * Use the proximity domain number as the device minor number.
	 * So the EGM corresponding to node X would be /dev/egmX.
	 */
	egm_chardev->egmphys = egmphys;
	egm_chardev->egmlength = egmlength;
	egm_chardev->egmpxm = egmpxm;
	INIT_LIST_HEAD(&egm_chardev->gpus);

	egm_chardev->device.devt = MKDEV(MAJOR(dev), egm_chardev->egmpxm);
	egm_chardev->device.class = class;
	egm_chardev->device.release = egm_chardev_release;
	cdev_init(&egm_chardev->cdev, &file_ops);
	egm_chardev->cdev.owner = THIS_MODULE;

	ret = dev_set_name(&egm_chardev->device, "egm%llu", egm_chardev->egmpxm);
	if (ret)
		goto error_exit;

	ret = cdev_device_add(&egm_chardev->cdev, &egm_chardev->device);
	if (ret)
		goto error_exit;

	return egm_chardev;

error_exit:
	put_device(&egm_chardev->device);
create_err:
	return NULL;
}

static void del_egm_chardev(struct nvgrace_egm_dev *egm_chardev)
{
	cdev_device_del(&egm_chardev->cdev, &egm_chardev->device);
	put_device(&egm_chardev->device);
}

static char *egm_devnode(const struct device *device, umode_t *mode)
{
	if (mode)
		*mode = 0600;

	return NULL;
}

static ssize_t egm_size_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct nvgrace_egm_dev *egm_dev =
		container_of(dev, struct nvgrace_egm_dev, device);

	return sysfs_emit(buf, "0x%zx\n", egm_dev->egmlength);
}

static DEVICE_ATTR_RO(egm_size);

static struct attribute *attrs[] = {
	&dev_attr_egm_size.attr,
	NULL,
};

static const struct attribute_group attr_group = {
	.attrs = attrs,
};

static const struct attribute_group *attr_groups[] = {
	&attr_group,
	NULL
};

/*
 * Determine if the EGM feature is enabled. If disabled, there
 * will be no EGM properties populated in the ACPI tables and this
 * fetch would fail.
 */
static int has_egm_property(struct pci_dev *pdev, u64 *pegmpxm)
{
	return device_property_read_u64(&pdev->dev, "nvidia,egm-pxm",
					pegmpxm);
}

static int fetch_egm_property(struct pci_dev *pdev, u64 *pegmphys,
			      u64 *pegmlength)
{
	int ret;

	/*
	 * The memory information is present in the system ACPI tables as DSD
	 * properties nvidia,egm-base-pa and nvidia,egm-size.
	 */
	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-size",
				       pegmlength);
	if (ret)
		return ret;

	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-base-pa",
				       pegmphys);

	return ret;
}

static struct nvgrace_egm_dev *get_egm_dev(u64 egmpxm)
{
	struct nvgrace_egm_dev_entry *egm_entry;

	list_for_each_entry(egm_entry, &egm_chardevs, list) {
		/*
		 * A system could have multiple GPUs associated with an
		 * EGM region and will have the same set of EGM region
		 * information. Return the existing EGM device if already
		 * registered through a different GPU on the same socket.
		 */
		if (egm_entry->egm_dev->egmpxm == egmpxm)
			return egm_entry->egm_dev;
	}

	return NULL;
}

static void nvgrace_egm_destroy_pci_devs(void)
{
	struct nvgrace_egm_dev_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &egm_chardevs, list) {
		list_del(&entry->list);
		del_egm_chardev(entry->egm_dev);
		kfree(entry);
	}
}

/*
 * Walk all PCI devices and for each one that has a companion ACPI object
 * advertising EGM properties, create an auxiliary device for that EGM range.
 * Multiple GPUs on the same socket share a single EGM region (same proximity
 * domain). So de-duplicate by skipping a pxm that is already registered.
 */
static int nvgrace_egm_create_pci_egm_devs(void)
{
	struct nvgrace_egm_dev_entry *egm_entry;
	struct nvgrace_egm_dev *egm_dev;
	struct pci_dev *pdev = NULL;
	int ret;

	for_each_pci_dev(pdev) {
		u64 egmphys, egmlength, egmpxm;

		if (has_egm_property(pdev, &egmpxm))
			continue;

		ret = fetch_egm_property(pdev, &egmphys, &egmlength);
		if (ret)
			continue;

		egm_dev = get_egm_dev(egmpxm);
		if (egm_dev) {
			ret = add_gpu(egm_dev, pdev);
			if (ret)
				goto free_dev;
			continue;
		}

		egm_entry = kzalloc_obj(*egm_entry, GFP_KERNEL);
		if (!egm_entry) {
			pci_dev_put(pdev);
			return -ENOMEM;
		}

		egm_dev = setup_egm_chardev(egmphys, egmlength, egmpxm);
		if (!egm_dev) {
			kfree(egm_entry);
			pci_dev_put(pdev);
			return -EINVAL;
		}

		egm_entry->egm_dev = egm_dev;

		ret = add_gpu(egm_entry->egm_dev, pdev);
		if (ret) {
			del_egm_chardev(egm_dev);
			kfree(egm_entry);
			goto free_dev;
		}

		list_add_tail(&egm_entry->list, &egm_chardevs);
	}

	return 0;

free_dev:
	/*
	 * Reached only via goto from inside the loop where the pdev still
	 * holds the reference from the last pci_get_device(). So drop it here.
	 */
	pci_dev_put(pdev);
	nvgrace_egm_destroy_pci_devs();
	return ret;
}

/*
 * The char device minor is the EGM proximity domain number which is sparse
 * and need not start at 0. Find the lowest proximity domain among the EGM
 * devices so the minor range can be reserved starting there. Returns -ENODEV
 * if the system has no EGM devices.
 *
 * EGM PXMs are assumed contiguous within [lowest, lowest + MAX_EGM_NODES),
 * which holds for the supported Grace configurations.
 */
static int nvgrace_egm_lowest_pxm(u64 *pmin_pxm)
{
	struct pci_dev *pdev = NULL;
	bool found = false;

	for_each_pci_dev(pdev) {
		u64 egmphys, egmlength, egmpxm;

		if (has_egm_property(pdev, &egmpxm))
			continue;

		if (fetch_egm_property(pdev, &egmphys, &egmlength))
			continue;

		if (!found || egmpxm < *pmin_pxm) {
			*pmin_pxm = egmpxm;
			found = true;
		}
	}

	if (!found)
		return -ENODEV;

	/*
	 * The PXM is used verbatim as the minor (only MINORBITS wide). Validate
	 * the window would not overflow MINORMASK and be truncated.
	 */
	if (*pmin_pxm + (MAX_EGM_NODES - 1) > MINORMASK) {
		pr_err("nvgrace-egm: lowest EGM proximity domain %llu\n"
		       "exceeds the minor range\n", *pmin_pxm);
		return -ERANGE;
	}

	return 0;
}

static int __init nvgrace_egm_init(void)
{
	u64 min_pxm;
	int ret;

	/*
	 * Each EGM region is exposed as /dev/egmX with the proximity domain X
	 * as its minor number. Reserve MAX_EGM_NODES minors starting at
	 * the lowest proximity domain so that every egmX device falls within
	 * the reserved range. With no EGM devices present, load without
	 * reserving any resources.
	 */
	ret = nvgrace_egm_lowest_pxm(&min_pxm);
	if (ret == -ENODEV)
		return 0;
	else if (ret)
		return ret;

	ret = alloc_chrdev_region(&dev, min_pxm, MAX_EGM_NODES,
				  NVGRACE_EGM_DEV_NAME);
	if (ret < 0)
		return ret;

	class = class_create(NVGRACE_EGM_DEV_NAME);
	if (IS_ERR(class)) {
		unregister_chrdev_region(dev, MAX_EGM_NODES);
		return PTR_ERR(class);
	}

	class->devnode = egm_devnode;
	class->dev_groups = attr_groups;

	ret = nvgrace_egm_create_pci_egm_devs();
	if (ret)
		goto cleanup_pci_devs;

	return 0;

cleanup_pci_devs:
	nvgrace_egm_destroy_pci_devs();
	class_destroy(class);
	unregister_chrdev_region(dev, MAX_EGM_NODES);

	return ret;
}

static void __exit nvgrace_egm_cleanup(void)
{
	/*
	 * When no EGM devices were present, the module loaded inertly and
	 * reserved nothing. @class stays NULL and there is nothing to undo.
	 */
	if (!class)
		return;

	nvgrace_egm_destroy_pci_devs();
	class_destroy(class);
	unregister_chrdev_region(dev, MAX_EGM_NODES);
}

module_init(nvgrace_egm_init);
module_exit(nvgrace_egm_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ankit Agrawal <ankita@nvidia.com>");
MODULE_DESCRIPTION("NVGRACE EGM - Module to support Extended GPU Memory on NVIDIA Grace Based systems");
