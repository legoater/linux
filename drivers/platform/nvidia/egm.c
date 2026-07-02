// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/mutex.h>
#include <linux/sched/signal.h>
#include <linux/sizes.h>
#include <linux/vfio_pci_core.h>
#include <linux/xarray.h>
#include <uapi/linux/egm.h>

#define NVGRACE_EGM_DEV_NAME "egm"
#define MAX_EGM_NODES 4

/*
 * Presence marker stored in nvgrace_egm_dev.retired_pages. Only the
 * page offset within the region carries information and the value
 * just needs to be a non-NULL xa entry.
 */
#define EGM_RETIRED_MARK xa_mk_value(1)

/*
 * The structure match the format of the retired pages information populated
 * by the system firmware.
 */
struct fw_egm_retired_pages {
	u64 num_retired_pages;
	__u64 retired_page_addr[4096];
};

static dev_t dev;
static struct class *class;

struct gpu_node {
	struct list_head list;
	struct pci_dev *pdev;
};

struct nvgrace_egm_dev {
	struct device device;
	struct cdev cdev;
	/* serialises the first-open scrub */
	struct mutex open_lock;
	/* protected by open_lock */
	unsigned int open_count;
	/*
	 * Set of retired page offsets within the
	 * EGM region and keyed by page index.
	 */
	struct xarray retired_pages;
	phys_addr_t egmphys;
	size_t egmlength;
	phys_addr_t retiredpagesphys;
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

static void cleanup_retired_pages(struct nvgrace_egm_dev *egm_dev);
static int nvgrace_egm_fetch_retired_pages(struct nvgrace_egm_dev *egm_dev);

static int nvgrace_egm_open(struct inode *inode, struct file *file)
{
	struct nvgrace_egm_dev *egm_dev =
		container_of(inode->i_cdev, struct nvgrace_egm_dev, cdev);
	phys_addr_t phys;
	size_t remaining, chunk_size;
	void *chunk_addr;
	int ret;

	file->private_data = egm_dev;

	/*
	 * The EGM region is a physical carveout handed to a single VM at a
	 * time and must be scrubbed before each handover. Take open_lock
	 * killably around the scrub which can run for long time, so that
	 * the waiters stay killable.
	 */
	if (mutex_lock_killable(&egm_dev->open_lock))
		return -EINTR;

	/*
	 * Refuse a second opener while the region is still held. release()
	 * runs only when the last reference to the struct file drops but an
	 * mmap keeps that reference (and hence open_count) alive past
	 * close for the lifetime of the VMA. So open_count returns to zero
	 * only when every mapping is gone. A concurrent opener cannot be
	 * handed the region: it cannot be re-scrubbed without destroying the
	 * current consumer's live data.
	 */
	if (egm_dev->open_count) {
		ret = -EBUSY;
		goto unlock;
	}

	/*
	 * nvgrace-egm module is responsible to manage the EGM memory as
	 * the host kernel has no knowledge of it. Clear the region before
	 * handing over to userspace.
	 *
	 * The EGM region can be very large (hundreds of GiB). So Map and zero
	 * one chunk at a time rather than mapping the whole region at once.
	 */
	phys = egm_dev->egmphys;
	remaining = egm_dev->egmlength;

	while (remaining > 0) {
		/*
		 * The scrub holds the lock for a long time; let it be
		 * SIGKILL'd.
		 */
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto unlock;
		}

		chunk_size = min(remaining, SZ_1G);

		chunk_addr = memremap(phys, chunk_size, MEMREMAP_WB);
		if (!chunk_addr) {
			ret = -ENOMEM;
			goto unlock;
		}

		memset(chunk_addr, 0, chunk_size);
		memunmap(chunk_addr);
		cond_resched();

		phys += chunk_size;
		remaining -= chunk_size;
	}

	/*
	 * Mark the device open only after the scrub completes so that a
	 * concurrent opener cannot observe a non-zero count and proceed
	 * before the region has been cleared.
	 */
	egm_dev->open_count = 1;
	ret = 0;

unlock:
	mutex_unlock(&egm_dev->open_lock);
	return ret;
}

static int nvgrace_egm_release(struct inode *inode, struct file *file)
{
	struct nvgrace_egm_dev *egm_dev =
		container_of(inode->i_cdev, struct nvgrace_egm_dev, cdev);

	guard(mutex)(&egm_dev->open_lock);

	if (!--egm_dev->open_count)
		file->private_data = NULL;

	return 0;
}

static int nvgrace_egm_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct nvgrace_egm_dev *egm_dev = file->private_data;
	u64 req_len, pgoff, end;
	unsigned long start_pfn, num_pages;

	pgoff = vma->vm_pgoff;
	num_pages = egm_dev->egmlength >> PAGE_SHIFT;

	/* Reject a page offset that already lies outside the EGM region. */
	if (pgoff >= num_pages)
		return -EINVAL;

	if (check_sub_overflow(vma->vm_end, vma->vm_start, &req_len) ||
	    check_add_overflow(PHYS_PFN(egm_dev->egmphys), pgoff, &start_pfn) ||
	    check_add_overflow(PFN_PHYS(pgoff), req_len, &end))
		return -EOVERFLOW;

	if (end > egm_dev->egmlength)
		return -EINVAL;

	/*
	 * EGM memory is invisible to the host kernel and is not managed
	 * by it. Map the usermode VMA to the EGM region.
	 */
	return remap_pfn_range(vma, vma->vm_start,
			       start_pfn, req_len,
			       vma->vm_page_prot);
}

static long nvgrace_egm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long minsz = offsetofend(struct egm_retired_pages_list, count);
	struct egm_retired_pages_list info;
	void __user *uarg = (void __user *)arg;
	struct nvgrace_egm_dev *egm_dev = file->private_data;

	if (copy_from_user(&info, uarg, minsz))
		return -EFAULT;

	if (info.argsz < minsz || !egm_dev)
		return -EINVAL;

	switch (cmd) {
	case EGM_RETIRED_PAGES_LIST: {
		unsigned long retired_page_struct_size = sizeof(struct egm_retired_pages_info);
		struct egm_retired_pages_info tmp;
		unsigned long page_index;
		void *entry;
		int count = 0, fill = 0;

		xa_for_each(&egm_dev->retired_pages, page_index, entry)
			count++;

		if (info.argsz < (minsz + count * retired_page_struct_size)) {
			info.argsz = minsz + count * retired_page_struct_size;
			info.count = 0;
			goto done;
		}

		xa_for_each(&egm_dev->retired_pages, page_index, entry) {
			if (fill >= count)
				break;

			tmp.offset = (u64)page_index << PAGE_SHIFT;
			tmp.size = PAGE_SIZE;

			if (copy_to_user((u8 __user *)uarg + minsz +
					 fill * retired_page_struct_size,
					 &tmp, retired_page_struct_size))
				return -EFAULT;

			fill++;
		}

		info.count = fill;
		break;
	}
	default:
		return -EINVAL;
	}

done:
	return copy_to_user(uarg, &info, minsz) ? -EFAULT : 0;
}

static const struct file_operations file_ops = {
	.owner = THIS_MODULE,
	.open = nvgrace_egm_open,
	.release = nvgrace_egm_release,
	.mmap = nvgrace_egm_mmap,
	.unlocked_ioctl = nvgrace_egm_ioctl,
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

	cleanup_retired_pages(egm_chardev);
	remove_gpus(egm_chardev);
	mutex_destroy(&egm_chardev->open_lock);
	kfree(egm_chardev);
}

static struct nvgrace_egm_dev *setup_egm_chardev(u64 egmphys, u64 egmlength,
						 u64 egmpxm,
						 u64 retiredpagesphys)
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
	egm_chardev->retiredpagesphys = retiredpagesphys;
	mutex_init(&egm_chardev->open_lock);
	xa_init(&egm_chardev->retired_pages);
	INIT_LIST_HEAD(&egm_chardev->gpus);

	egm_chardev->device.devt = MKDEV(MAJOR(dev), egm_chardev->egmpxm);
	egm_chardev->device.class = class;
	egm_chardev->device.release = egm_chardev_release;
	cdev_init(&egm_chardev->cdev, &file_ops);
	egm_chardev->cdev.owner = THIS_MODULE;

	ret = dev_set_name(&egm_chardev->device, "egm%llu", egm_chardev->egmpxm);
	if (ret)
		goto error_exit;

	ret = nvgrace_egm_fetch_retired_pages(egm_chardev);
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

static void cleanup_retired_pages(struct nvgrace_egm_dev *egm_dev)
{
	/* Entries are value marks, so xa_destroy() frees the table itself. */
	xa_destroy(&egm_dev->retired_pages);
}

static int nvgrace_egm_fetch_retired_pages(struct nvgrace_egm_dev *egm_dev)
{
	struct fw_egm_retired_pages *egm_retired;
	u64 count;
	int index, ret = 0;

	/* No retired-pages region was advertised; nothing to populate. */
	if (!egm_dev->retiredpagesphys)
		return 0;

	egm_retired = memremap(egm_dev->retiredpagesphys,
			       sizeof(*egm_retired), MEMREMAP_WB);
	if (!egm_retired)
		return -ENOMEM;

	count = egm_retired->num_retired_pages;
	if (count > ARRAY_SIZE(egm_retired->retired_page_addr)) {
		memunmap(egm_retired);
		return -EINVAL;
	}

	for (index = 0; index < count && !ret; index++) {
		phys_addr_t base = egm_retired->retired_page_addr[index];
		int sub;

		/*
		 * Entries come from SBIOS. Skip any base outside the EGM
		 * region [egmphys, egmphys + egmlength).
		 */
		if (base < egm_dev->egmphys ||
		    base >= egm_dev->egmphys + egm_dev->egmlength) {
			dev_warn_ratelimited(&egm_dev->device,
					     "Ignoring retired page %pa outside EGM region\n",
					     &base);
			continue;
		}

		/*
		 * Since the EGM is linearly mapped, the offset in the
		 * carveout is the same offset in the VM system memory.
		 *
		 * Calculate the offset to communicate to the usermode
		 * apps.
		 *
		 * The retired page entry represent a retired region of
		 * size 64K. So on a 4K kernel, each entry spans 0x10
		 * 4K sub-pages; add one entry per sub-page so that any
		 * lookup at 4K granularity hits the right retired range.
		 */
		for (sub = 0; sub < SZ_64K / PAGE_SIZE; sub++) {
			unsigned long offset = base +
				(phys_addr_t)sub * PAGE_SIZE - egm_dev->egmphys;
			void *old;

			old = xa_store(&egm_dev->retired_pages,
				       offset >> PAGE_SHIFT, EGM_RETIRED_MARK,
				       GFP_KERNEL);
			if (xa_is_err(old)) {
				ret = xa_err(old);
				break;
			}
		}
	}

	memunmap(egm_retired);

	/*
	 * On failure the partially populated table is freed by
	 * egm_chardev_release() via the caller's error path.
	 */
	return ret;
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
			      u64 *pegmlength, u64 *pretiredpagesphys)
{
	int ret;

	/*
	 * The EGM memory information is present in the system ACPI tables
	 * as DSD properties nvidia,egm-base-pa and nvidia,egm-size.
	 */
	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-size",
				       pegmlength);
	if (ret)
		goto error_exit;

	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-base-pa",
				       pegmphys);
	if (ret)
		goto error_exit;

	/*
	 * SBIOS puts the list of retired pages on a region exposed as
	 * "nvidia,egm-retired-pages-data-base". Older firmware may not expose
	 * it. Treat an absent or zero property as 0 retired pages so the
	 * EGM device is still created (with an empty retired-pages table).
	 */
	ret = device_property_read_u64(&pdev->dev,
				       "nvidia,egm-retired-pages-data-base",
				       pretiredpagesphys);
	if (ret) {
		*pretiredpagesphys = 0;
		ret = 0;
	}

error_exit:
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
		u64 egmphys, egmlength, egmpxm, retiredpagesphys;

		if (has_egm_property(pdev, &egmpxm))
			continue;

		ret = fetch_egm_property(pdev, &egmphys, &egmlength,
					 &retiredpagesphys);
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

		egm_dev = setup_egm_chardev(egmphys, egmlength, egmpxm,
					    retiredpagesphys);
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
		u64 egmphys, egmlength, egmpxm, retiredpagesphys;

		if (has_egm_property(pdev, &egmpxm))
			continue;

		if (fetch_egm_property(pdev, &egmphys, &egmlength,
				       &retiredpagesphys))
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
