// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/anon_inodes.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>
#include <net/sock.h>

struct igbvf_state {
	u64 magic;
#define IGBVF_MAGIC 0x69676276666d6967 /* igbvfmig */
	u8 mac_addr[ETH_ALEN];
};

struct igbvf_migration_file {
	struct file *filp;
	struct mutex lock;
	bool disabled;
	u8 *mig_data;
	size_t size;
};

struct igbvf_pci_core_device {
	struct vfio_pci_core_device core_device;
	struct pci_dev *pdev;

	int vf_id;
	u8 migrate_cap:1;
	u8 deferred_reset:1;
	/* protect migration state */
	struct mutex state_mutex;
	enum vfio_device_mig_state mig_state;
	/* protect the reset_done flow */
	spinlock_t reset_lock;
	struct igbvf_migration_file *resuming_migf;
	struct igbvf_migration_file *saving_migf;
};

#define MAX_MIGRATION_SIZE (256 * 1024)

static int igbvf_cmd_suspend_device(struct igbvf_pci_core_device *igbvf_dev)
{
	struct pci_dev *pdev = igbvf_dev->pdev;
	int ret = 0;

	dev_dbg(&pdev->dev, "suspend\n");

#ifdef CONFIG_PM_SLEEP
	ret = pm_generic_suspend(&pdev->dev);
#endif
	if (ret)
		dev_warn(&pdev->dev, "Suspend virtual function failed (ret=0x%x)\n", ret);
	return ret;
}

static int igbvf_cmd_resume_device(struct igbvf_pci_core_device *igbvf_dev)
{
	struct pci_dev *pdev = igbvf_dev->pdev;
	int ret = 0;

	dev_dbg(&pdev->dev, "resume\n");

#ifdef CONFIG_PM_SLEEP
	ret = pm_generic_resume(&pdev->dev);
#endif
	if (ret)
		dev_warn(&pdev->dev, "Resume virtual function failed (ret=0x%x)\n", ret);
	return ret;
}

static int igbvf_cmd_query_data_size(struct igbvf_pci_core_device *igbvf_dev,
					  size_t *state_size)
{
	*state_size = sizeof(struct igbvf_state);
	return 0;
}

static int igbvf_cmd_save_mac_addr(struct net_device *netdev, struct igbvf_state *igbvf_state)
{
	if (!netdev->addr_len)
		memset(igbvf_state->mac_addr, 0, sizeof(igbvf_state->mac_addr));
	else {
		netdev_info(netdev, "MAC: %pM\n", netdev->dev_addr);
		memcpy(igbvf_state->mac_addr, netdev->dev_addr,
		       min_t(size_t, netdev->addr_len, sizeof(igbvf_state->mac_addr)));
	}
	return 0;
}

static int igbvf_cmd_save_data(struct igbvf_pci_core_device *igbvf_dev,
				    void *buffer, size_t buffer_len)
{
	struct pci_dev *pdev = igbvf_dev->pdev;
	struct igbvf_state *igbvf_state = buffer;
	struct net_device *netdev = pci_get_drvdata(pdev);
	int ret;

	dev_dbg(&pdev->dev, "get migration state\n");
	igbvf_state->magic = IGBVF_MAGIC;

	ret = igbvf_cmd_save_mac_addr(netdev, igbvf_state);
	if (ret < 0)
		netdev_warn(netdev, "Saving mac address failed\n");
	return ret;
}

static int igbvf_cmd_load_vf_mac(struct net_device *netdev, int vf, u8 *mac)
{
	const struct net_device_ops *ops = netdev->netdev_ops;

	if (ops->ndo_set_vf_mac)
		return ops->ndo_set_vf_mac(netdev, vf, mac);
	return -EOPNOTSUPP;
}

static int igbvf_cmd_load_data(struct igbvf_pci_core_device *igbvf_dev,
				    struct igbvf_migration_file *migf)
{
	struct pci_dev *pdev = igbvf_dev->pdev;
	struct igbvf_state *igbvf_state = (struct igbvf_state*) migf->mig_data;
	struct net_device *pfdev = pci_get_drvdata(pdev->physfn);
	int ret;

	dev_dbg(&pdev->dev, "set migration state\n");
	if (igbvf_state->magic != IGBVF_MAGIC) {
		dev_err(&pdev->dev, "invalid state\n");
		return -EINVAL;
	}

	ret = igbvf_cmd_load_vf_mac(pfdev, igbvf_dev->vf_id, igbvf_state->mac_addr);
	if (ret < 0)
		netdev_warn(pfdev, "Loading mac address failed\n");

	return ret;
}

static struct igbvf_pci_core_device *igbvf_drvdata(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

	return container_of(core_device, struct igbvf_pci_core_device, core_device);
}

static void igbvf_disable_fd(struct igbvf_migration_file *migf)
{
	mutex_lock(&migf->lock);

	/* release the device states buffer */
	kvfree(migf->mig_data);
	migf->mig_data = NULL;
	migf->disabled = true;
	migf->size = 0;
	migf->filp->f_pos = 0;
	mutex_unlock(&migf->lock);
}

static int igbvf_release_file(struct inode *inode, struct file *filp)
{
	struct igbvf_migration_file *migf = filp->private_data;

	igbvf_disable_fd(migf);
	mutex_destroy(&migf->lock);
	kfree(migf);
	return 0;
}

static ssize_t igbvf_save_read(struct file *filp, char __user *buf, size_t len, loff_t *pos)
{
	struct igbvf_migration_file *migf = filp->private_data;
	ssize_t done = 0;
	int ret;

	if (pos)
		return -ESPIPE;
	pos = &filp->f_pos;

	mutex_lock(&migf->lock);
	if (*pos > migf->size) {
		done = -EINVAL;
		goto out_unlock;
	}

	if (migf->disabled) {
		done = -EINVAL;
		goto out_unlock;
	}

	len = min_t(size_t, migf->size - *pos, len);
	if (len) {
		ret = copy_to_user(buf, migf->mig_data + *pos, len);
		if (ret) {
			done = -EFAULT;
			goto out_unlock;
		}
		*pos += len;
		done = len;
	}

out_unlock:
	mutex_unlock(&migf->lock);
	return done;
}

static const struct file_operations igbvf_save_fops = {
	.owner = THIS_MODULE,
	.read = igbvf_save_read,
	.release = igbvf_release_file,
};

static ssize_t igbvf_resume_write(struct file *filp, const char __user *buf,
				       size_t len, loff_t *pos)
{
	struct igbvf_migration_file *migf = filp->private_data;
	loff_t requested_length;
	ssize_t done = 0;
	int ret;

	if (pos)
		return -ESPIPE;
	pos = &filp->f_pos;

	if (*pos < 0 || check_add_overflow((loff_t)len, *pos, &requested_length))
		return -EINVAL;

	if (requested_length > MAX_MIGRATION_SIZE)
		return -ENOMEM;
	mutex_lock(&migf->lock);
	if (migf->disabled) {
		done = -ENODEV;
		goto out_unlock;
	}

	ret = copy_from_user(migf->mig_data + *pos, buf, len);
	if (ret) {
		done = -EFAULT;
		goto out_unlock;
	}
	*pos += len;
	done = len;
	migf->size += len;

out_unlock:
	mutex_unlock(&migf->lock);
	return done;
}

static const struct file_operations igbvf_resume_fops = {
	.owner = THIS_MODULE,
	.write = igbvf_resume_write,
	.release = igbvf_release_file,
};

static void igbvf_disable_fds(struct igbvf_pci_core_device *igbvf_dev)
{
	if (igbvf_dev->resuming_migf) {
		igbvf_disable_fd(igbvf_dev->resuming_migf);
		fput(igbvf_dev->resuming_migf->filp);
		igbvf_dev->resuming_migf = NULL;
	}

	if (igbvf_dev->saving_migf) {
		igbvf_disable_fd(igbvf_dev->saving_migf);
		fput(igbvf_dev->saving_migf->filp);
		igbvf_dev->saving_migf = NULL;
	}
}

static struct igbvf_migration_file *
igbvf_pci_resume_device_data(struct igbvf_pci_core_device *igbvf_dev)
{
	struct pci_dev *pdev = igbvf_dev->pdev;
	struct igbvf_migration_file *migf;
	int ret;

	dev_dbg(&pdev->dev, "set restore file\n");

	migf = kzalloc(sizeof(*migf), GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("igbvf_mig", &igbvf_resume_fops, migf,
					O_WRONLY);
	if (IS_ERR(migf->filp)) {
		int err = PTR_ERR(migf->filp);

		kfree(migf);
		return ERR_PTR(err);
	}
	stream_open(migf->filp->f_inode, migf->filp);
	mutex_init(&migf->lock);

	/* Allocate buffer to load the device state */
	migf->mig_data = kvzalloc(MAX_MIGRATION_SIZE, GFP_KERNEL);
	if (!migf->mig_data) {
		ret = -ENOMEM;
		goto out_free;
	}

	return migf;

out_free:
	fput(migf->filp);
	return ERR_PTR(ret);
}

static struct igbvf_migration_file *
igbvf_pci_save_device_data(struct igbvf_pci_core_device *igbvf_dev)
{
	struct pci_dev *pdev = igbvf_dev->pdev;
	struct igbvf_migration_file *migf;
	size_t size;
	int ret;

	ret = igbvf_cmd_query_data_size(igbvf_dev, &size);
	if (ret) {
		dev_err(&pdev->dev, "failed to get save state: %pe\n",
			ERR_PTR(ret));
		return ERR_PTR(ret);
	}

	dev_dbg(&pdev->dev, "set save file, size = %ld\n", size);

	if (!size) {
		dev_err(&pdev->dev, "invalid state size\n");
		return ERR_PTR(-EIO);
	}

	migf = kzalloc(sizeof(*migf), GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("igbvf_mig", &igbvf_save_fops, migf,
					O_RDONLY);
	if (IS_ERR(migf->filp)) {
		int err = PTR_ERR(migf->filp);

		kfree(migf);
		return ERR_PTR(err);
	}

	stream_open(migf->filp->f_inode, migf->filp);
	mutex_init(&migf->lock);
	migf->size = PAGE_ALIGN(size);

	/* Allocate buffer and save the device states */
	migf->mig_data = kvzalloc(migf->size, GFP_KERNEL);
	if (!migf->mig_data) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = igbvf_cmd_save_data(igbvf_dev, migf->mig_data, migf->size);
	if (ret)
		goto out_free;

	return migf;
out_free:
	fput(migf->filp);
	return ERR_PTR(ret);
}

static const char *vfio_device_mig_state_str(enum vfio_device_mig_state state)
{
	switch (state) {
	case VFIO_DEVICE_STATE_ERROR:
		return "VFIO_DEVICE_STATE_ERROR";
	case VFIO_DEVICE_STATE_STOP:
		return "VFIO_DEVICE_STATE_STOP";
	case VFIO_DEVICE_STATE_RUNNING:
		return "VFIO_DEVICE_STATE_RUNNING";
	case VFIO_DEVICE_STATE_STOP_COPY:
		return "VFIO_DEVICE_STATE_STOP_COPY";
	case VFIO_DEVICE_STATE_RESUMING:
		return "VFIO_DEVICE_STATE_RESUMING";
	case VFIO_DEVICE_STATE_RUNNING_P2P:
		return "VFIO_DEVICE_STATE_RUNNING_P2P";
	default:
		return "VFIO_DEVICE_STATE_INVALID";
	}

	return "VFIO_DEVICE_STATE_INVALID";
}

static struct file *
igbvf_pci_step_device_state_locked(struct igbvf_pci_core_device *igbvf_dev, u32 new)
{
	struct pci_dev *pdev = igbvf_dev->pdev;
	u32 cur = igbvf_dev->mig_state;
	int ret;

	dev_dbg(&pdev->dev, "%s => %s\n", vfio_device_mig_state_str(cur),
		vfio_device_mig_state_str(new));

	if (cur == VFIO_DEVICE_STATE_RUNNING && new == VFIO_DEVICE_STATE_STOP) {
		ret = igbvf_cmd_suspend_device(igbvf_dev);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_STOP_COPY) {
		struct igbvf_migration_file *migf;

		migf = igbvf_pci_save_device_data(igbvf_dev);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		igbvf_dev->saving_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_STOP_COPY && new == VFIO_DEVICE_STATE_STOP) {
		igbvf_disable_fds(igbvf_dev);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RESUMING) {
		struct igbvf_migration_file *migf;

		migf = igbvf_pci_resume_device_data(igbvf_dev);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		igbvf_dev->resuming_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_RESUMING && new == VFIO_DEVICE_STATE_STOP) {
		ret = igbvf_cmd_load_data(igbvf_dev, igbvf_dev->resuming_migf);
		if (ret)
			return ERR_PTR(ret);
		igbvf_disable_fds(igbvf_dev);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RUNNING) {
		igbvf_cmd_resume_device(igbvf_dev);
		return NULL;
	}

	WARN_ON(true);
	return ERR_PTR(-EINVAL);
}

static void igbvf_state_mutex_unlock(struct igbvf_pci_core_device *igbvf_dev)
{
again:
	spin_lock(&igbvf_dev->reset_lock);
	if (igbvf_dev->deferred_reset) {
		igbvf_dev->deferred_reset = false;
		spin_unlock(&igbvf_dev->reset_lock);
		igbvf_dev->mig_state = VFIO_DEVICE_STATE_RUNNING;
		igbvf_disable_fds(igbvf_dev);
		goto again;
	}
	mutex_unlock(&igbvf_dev->state_mutex);
	spin_unlock(&igbvf_dev->reset_lock);
}

static struct file *
igbvf_pci_set_device_state(struct vfio_device *vdev,
			   enum vfio_device_mig_state new_state)
{
	struct igbvf_pci_core_device *igbvf_dev = container_of(vdev,
			struct igbvf_pci_core_device, core_device.vdev);
	enum vfio_device_mig_state next_state;
	struct file *res = NULL;
	int ret;

	mutex_lock(&igbvf_dev->state_mutex);
	while (new_state != igbvf_dev->mig_state) {
		ret = vfio_mig_get_next_state(vdev, igbvf_dev->mig_state, new_state, &next_state);
		if (ret) {
			res = ERR_PTR(-EINVAL);
			break;
		}

		res = igbvf_pci_step_device_state_locked(igbvf_dev, next_state);
		if (IS_ERR(res))
			break;
		igbvf_dev->mig_state = next_state;
		if (WARN_ON(res && new_state != igbvf_dev->mig_state)) {
			fput(res);
			res = ERR_PTR(-EINVAL);
			break;
		}
	}
	igbvf_state_mutex_unlock(igbvf_dev);
	return res;
}

static int igbvf_pci_get_device_state(struct vfio_device *vdev,
					   enum vfio_device_mig_state *curr_state)
{
	struct igbvf_pci_core_device *igbvf_dev = container_of(
			vdev, struct igbvf_pci_core_device, core_device.vdev);

	mutex_lock(&igbvf_dev->state_mutex);
	*curr_state = igbvf_dev->mig_state;
	igbvf_state_mutex_unlock(igbvf_dev);
	return 0;
}

static int igbvf_pci_get_data_size(struct vfio_device *vdev,
				    unsigned long *stop_copy_length)
{
	struct igbvf_pci_core_device *igbvf_dev = container_of(
		vdev, struct igbvf_pci_core_device, core_device.vdev);
	struct pci_dev *pdev = to_pci_dev(vdev->dev);
	size_t state_size;
	int ret;

	mutex_lock(&igbvf_dev->state_mutex);
	ret = igbvf_cmd_query_data_size(igbvf_dev, &state_size);
	if (!ret)
		*stop_copy_length = state_size;
	igbvf_state_mutex_unlock(igbvf_dev);
	dev_dbg(&pdev->dev, "%s() -> size:%ld", __func__, state_size);
	return ret;
}

static int igbvf_pci_open_device(struct vfio_device *core_vdev)
{
	struct igbvf_pci_core_device *igbvf_dev = container_of(
			core_vdev, struct igbvf_pci_core_device, core_device.vdev);
	struct vfio_pci_core_device *core_device = &igbvf_dev->core_device;
	int ret;

	ret = vfio_pci_core_enable(core_device);
	if (ret)
		return ret;

	if (igbvf_dev->migrate_cap)
		igbvf_dev->mig_state = VFIO_DEVICE_STATE_RUNNING;

	vfio_pci_core_finish_enable(core_device);
	return 0;
}

static void igbvf_cmd_close_migratable(struct igbvf_pci_core_device *igbvf_dev)
{
	if (!igbvf_dev->migrate_cap)
		return;

	mutex_lock(&igbvf_dev->state_mutex);
	igbvf_disable_fds(igbvf_dev);
	igbvf_state_mutex_unlock(igbvf_dev);
}

static void igbvf_pci_close_device(struct vfio_device *core_vdev)
{
	struct igbvf_pci_core_device *igbvf_dev = container_of(
			core_vdev, struct igbvf_pci_core_device, core_device.vdev);

	igbvf_cmd_close_migratable(igbvf_dev);
	vfio_pci_core_close_device(core_vdev);
}

static bool igbvf_check_migration(struct pci_dev *pdev)
{
	return true;
}

static const struct vfio_migration_ops igbvf_pci_mig_ops = {
	.migration_set_state = igbvf_pci_set_device_state,
	.migration_get_state = igbvf_pci_get_device_state,
	.migration_get_data_size = igbvf_pci_get_data_size,
};

static int igbvf_pci_dirty_enable(struct igbvf_pci_core_device *igbvf_dev,
				 struct rb_root_cached *ranges, u32 nnodes,
				 u64 *page_size)
{
	struct pci_dev *pdev = igbvf_dev->pdev;

	dev_dbg(&pdev->dev, "vf%u: Start dirty page tracking\n", igbvf_dev->vf_id);
	return 0;
}

static int igbvf_pci_dirty_disable(struct igbvf_pci_core_device *igbvf_dev)
{
	struct pci_dev *pdev = igbvf_dev->pdev;

	dev_dbg(&pdev->dev, "vf%u: Start dirty page tracking\n", igbvf_dev->vf_id);
	return 0;
}

static int igbvf_pci_dirty_sync(struct igbvf_pci_core_device *igbvf_dev,
				struct iova_bitmap *dirty_bitmap,
				unsigned long iova, unsigned long length)
{
	struct pci_dev *pdev = igbvf_dev->pdev;

	dev_dbg(&pdev->dev, "vf%u: Start dirty page tracking\n", igbvf_dev->vf_id);
	return 0;
}

static int igbvf_pci_dma_log_read_and_clear(struct vfio_device *core_vdev,
					    unsigned long iova, unsigned long length,
					    struct iova_bitmap *dirty)
{
	struct igbvf_pci_core_device *igbvf_dev =
		container_of(core_vdev, struct igbvf_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&igbvf_dev->state_mutex);
	ret = igbvf_pci_dirty_sync(igbvf_dev, dirty, iova, length);
	igbvf_state_mutex_unlock(igbvf_dev);

	return ret;
}

static int igbvf_pci_dma_log_start(struct vfio_device *core_vdev,
				      struct rb_root_cached *ranges, u32 nnodes,
				      u64 *page_size)
{
	struct igbvf_pci_core_device *igbvf_dev =
		container_of(core_vdev, struct igbvf_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&igbvf_dev->state_mutex);
	ret = igbvf_pci_dirty_enable(igbvf_dev, ranges, nnodes, page_size);
	igbvf_state_mutex_unlock(igbvf_dev);

	return ret;
}

static int igbvf_pci_dma_log_stop(struct vfio_device *core_vdev)
{
	struct igbvf_pci_core_device *igbvf_dev =
		container_of(core_vdev, struct igbvf_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&igbvf_dev->state_mutex);
	ret = igbvf_pci_dirty_disable(igbvf_dev);
	igbvf_state_mutex_unlock(igbvf_dev);

	return ret;
}

static const struct vfio_log_ops igbvf_pci_log_ops = {
	.log_start = igbvf_pci_dma_log_start,
	.log_stop = igbvf_pci_dma_log_stop,
	.log_read_and_clear = igbvf_pci_dma_log_read_and_clear,
};

static int igbvf_vfio_pci_init_dev(struct vfio_device *core_vdev)
{
	struct igbvf_pci_core_device *igbvf_dev = container_of(core_vdev,
				 struct igbvf_pci_core_device, core_device.vdev);
	struct pci_dev *pdev = to_pci_dev(core_vdev->dev);
	int ret = -1;

	if (!pdev->is_virtfn) {
		dev_err(&pdev->dev, "not a VF");
		return ret;
	}

	if (!igbvf_check_migration(pdev))
		return ret;

	igbvf_dev->migrate_cap = 1;

	igbvf_dev->vf_id = pci_iov_vf_id(pdev);

	mutex_init(&igbvf_dev->state_mutex);
	spin_lock_init(&igbvf_dev->reset_lock);

	core_vdev->migration_flags = VFIO_MIGRATION_STOP_COPY;
	core_vdev->mig_ops = &igbvf_pci_mig_ops;
	core_vdev->log_ops = &igbvf_pci_log_ops;

	return vfio_pci_core_init_dev(core_vdev);
}


static const struct vfio_device_ops igbvf_vfio_pci_ops = {
	.name = "igbvf-vfio-pci",
	.init = igbvf_vfio_pci_init_dev,
	.release = vfio_pci_core_release_dev,
	.open_device = igbvf_pci_open_device,
	.close_device = igbvf_pci_close_device,
	.ioctl = vfio_pci_core_ioctl,
	.device_feature = vfio_pci_core_ioctl_feature,
	.read = vfio_pci_core_read,
	.write = vfio_pci_core_write,
	.mmap = vfio_pci_core_mmap,
	.request = vfio_pci_core_request,
	.match = vfio_pci_core_match,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
	.match_token_uuid = vfio_pci_core_match_token_uuid,
#endif
	.bind_iommufd	= vfio_iommufd_physical_bind,
	.unbind_iommufd	= vfio_iommufd_physical_unbind,
	.attach_ioas	= vfio_iommufd_physical_attach_ioas,
	.detach_ioas	= vfio_iommufd_physical_detach_ioas,
};

static int igbvf_vfio_pci_probe(struct pci_dev *pdev,
			      const struct pci_device_id *id)
{
	struct igbvf_pci_core_device *igbvf_dev;
	int ret;

	igbvf_dev = vfio_alloc_device(igbvf_pci_core_device, core_device.vdev,
				  &pdev->dev, &igbvf_vfio_pci_ops);
	if (IS_ERR(igbvf_dev))
		return PTR_ERR(igbvf_dev);

	dev_set_drvdata(&pdev->dev, &igbvf_dev->core_device);
	igbvf_dev->pdev = pdev;

	ret = vfio_pci_core_register_device(&igbvf_dev->core_device);
	if (ret)
		goto out_put_vdev;
	return 0;

out_put_vdev:
	vfio_put_device(&igbvf_dev->core_device.vdev);
	return ret;
}

static void igbvf_vfio_pci_remove(struct pci_dev *pdev)
{
	struct igbvf_pci_core_device *igbvf_dev = igbvf_drvdata(pdev);

	vfio_pci_core_unregister_device(&igbvf_dev->core_device);
	vfio_put_device(&igbvf_dev->core_device.vdev);
}

static void igbvf_vfio_pci_aer_reset_done(struct pci_dev *pdev)
{
	struct igbvf_pci_core_device *igbvf_dev = igbvf_drvdata(pdev);

	if (!igbvf_dev->migrate_cap)
		return;

	/*
	 * As the higher VFIO layers are holding locks across reset and using
	 * those same locks with the mm_lock we need to prevent ABBA deadlock
	 * with the state_mutex and mm_lock.
	 * In case the state_mutex was taken already we defer the cleanup work
	 * to the unlock flow of the other running context.
	 */
	spin_lock(&igbvf_dev->reset_lock);
	igbvf_dev->deferred_reset = true;
	if (!mutex_trylock(&igbvf_dev->state_mutex)) {
		spin_unlock(&igbvf_dev->reset_lock);
		return;
	}
	spin_unlock(&igbvf_dev->reset_lock);
	igbvf_state_mutex_unlock(igbvf_dev);
}

static const struct pci_device_id igbvf_vfio_pci_table[] = {
	/* Intel Corporation 82576 Gigabit Network Connection */
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_INTEL, 0x10ca) },
	{}
};

MODULE_DEVICE_TABLE(pci, igbvf_vfio_pci_table);

static const struct pci_error_handlers igbvf_err_handlers = {
	.reset_done = igbvf_vfio_pci_aer_reset_done,
	.error_detected = vfio_pci_core_aer_err_detected,
};

static struct pci_driver igbvf_vfio_pci_driver = {
	.name = "igbvf-vfio-pci",
	.id_table = igbvf_vfio_pci_table,
	.probe = igbvf_vfio_pci_probe,
	.remove = igbvf_vfio_pci_remove,
	.err_handler = &igbvf_err_handlers,
	.driver_managed_dma = true,
};

module_pci_driver(igbvf_vfio_pci_driver);

MODULE_IMPORT_NS("IOMMUFD");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cédric Le Goater <clg@redhat.com>");
MODULE_DESCRIPTION("VFIO PCI - Intel Corporation 82576 Virtual Function");
