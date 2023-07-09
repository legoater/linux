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
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

struct e1000e_state {
	u64 magic;
#define E1000E_MAGIC 0x6531303030653030 /* e1000e00 */
};

struct e1000e_migration_file {
	struct file *filp;
	struct mutex lock;
	bool disabled;
	u8 *mig_data;
	size_t size;
};

struct e1000e_pci_core_device {
	struct vfio_pci_core_device core_device;
	struct pci_dev *pdev;

	u8 migrate_cap:1;
	u8 deferred_reset:1;
	/* protect migration state */
	struct mutex state_mutex;
	enum vfio_device_mig_state mig_state;
	/* protect the reset_done flow */
	spinlock_t reset_lock;
	struct e1000e_migration_file *resuming_migf;
	struct e1000e_migration_file *saving_migf;
};

#define MAX_MIGRATION_SIZE (256 * 1024)

static int e1000e_cmd_suspend_device(struct e1000e_pci_core_device *e1000e_dev)
{
	struct pci_dev *pdev = e1000e_dev->pdev;

	dev_dbg(&pdev->dev, "suspend\n");
	return 0;
}

static int e1000e_cmd_resume_device(struct e1000e_pci_core_device *e1000e_dev)
{
	struct pci_dev *pdev = e1000e_dev->pdev;

	dev_dbg(&pdev->dev, "resume\n");
	return 0;
}

static int e1000e_cmd_query_data_size(struct e1000e_pci_core_device *e1000e_dev,
				      size_t *state_size)
{
	*state_size = sizeof(struct e1000e_state);
	return 0;
}

static int e1000e_cmd_save_data(struct e1000e_pci_core_device *e1000e_dev,
				void *buffer, size_t buffer_len)
{
	struct pci_dev *pdev = e1000e_dev->pdev;
	struct e1000e_state *e1000e_state = buffer;

	dev_dbg(&pdev->dev, "get migration state\n");
	e1000e_state->magic = E1000E_MAGIC;
	return 0;
}

static int e1000e_cmd_load_data(struct e1000e_pci_core_device *e1000e_dev,
				struct e1000e_migration_file *migf)
{
	struct pci_dev *pdev = e1000e_dev->pdev;
	struct e1000e_state *e1000e_state = (struct e1000e_state*) migf->mig_data;

	dev_dbg(&pdev->dev, "set migration state\n");

	if (e1000e_state->magic != E1000E_MAGIC) {
		dev_err(&pdev->dev, "invalid state\n");
		return -EINVAL;
	}

	return 0;
}

static struct e1000e_pci_core_device *e1000e_drvdata(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

	return container_of(core_device, struct e1000e_pci_core_device, core_device);
}

static void e1000e_disable_fd(struct e1000e_migration_file *migf)
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

static int e1000e_release_file(struct inode *inode, struct file *filp)
{
	struct e1000e_migration_file *migf = filp->private_data;

	e1000e_disable_fd(migf);
	mutex_destroy(&migf->lock);
	kfree(migf);
	return 0;
}

static ssize_t e1000e_save_read(struct file *filp, char __user *buf, size_t len, loff_t *pos)
{
	struct e1000e_migration_file *migf = filp->private_data;
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

static const struct file_operations e1000e_save_fops = {
	.owner = THIS_MODULE,
	.read = e1000e_save_read,
	.release = e1000e_release_file,
	.llseek = no_llseek,
};

static ssize_t e1000e_resume_write(struct file *filp, const char __user *buf,
				   size_t len, loff_t *pos)
{
	struct e1000e_migration_file *migf = filp->private_data;
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

static const struct file_operations e1000e_resume_fops = {
	.owner = THIS_MODULE,
	.write = e1000e_resume_write,
	.release = e1000e_release_file,
	.llseek = no_llseek,
};

static void e1000e_disable_fds(struct e1000e_pci_core_device *e1000e_dev)
{
	if (e1000e_dev->resuming_migf) {
		e1000e_disable_fd(e1000e_dev->resuming_migf);
		fput(e1000e_dev->resuming_migf->filp);
		e1000e_dev->resuming_migf = NULL;
	}

	if (e1000e_dev->saving_migf) {
		e1000e_disable_fd(e1000e_dev->saving_migf);
		fput(e1000e_dev->saving_migf->filp);
		e1000e_dev->saving_migf = NULL;
	}
}

static struct e1000e_migration_file *
e1000e_pci_resume_device_data(struct e1000e_pci_core_device *e1000e_dev)
{
	struct pci_dev *pdev = e1000e_dev->pdev;
	struct e1000e_migration_file *migf;
	int ret;

	dev_dbg(&pdev->dev, "set restore file\n");

	migf = kzalloc(sizeof(*migf), GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("e1000e_mig", &e1000e_resume_fops, migf,
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

static struct e1000e_migration_file *
e1000e_pci_save_device_data(struct e1000e_pci_core_device *e1000e_dev)
{
	struct pci_dev *pdev = e1000e_dev->pdev;
	struct e1000e_migration_file *migf;
	size_t size;
	int ret;

	ret = e1000e_cmd_query_data_size(e1000e_dev, &size);
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

	migf->filp = anon_inode_getfile("e1000e_mig", &e1000e_save_fops, migf,
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

	ret = e1000e_cmd_save_data(e1000e_dev, migf->mig_data, migf->size);
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
e1000e_pci_step_device_state_locked(struct e1000e_pci_core_device *e1000e_dev, u32 new)
{
	struct pci_dev *pdev = e1000e_dev->pdev;
	u32 cur = e1000e_dev->mig_state;
	int ret;

	dev_dbg(&pdev->dev, "%s => %s\n", vfio_device_mig_state_str(cur),
		vfio_device_mig_state_str(new));

	if (cur == VFIO_DEVICE_STATE_RUNNING && new == VFIO_DEVICE_STATE_STOP) {
		ret = e1000e_cmd_suspend_device(e1000e_dev);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_STOP_COPY) {
		struct e1000e_migration_file *migf;

		migf = e1000e_pci_save_device_data(e1000e_dev);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		e1000e_dev->saving_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_STOP_COPY && new == VFIO_DEVICE_STATE_STOP) {
		e1000e_disable_fds(e1000e_dev);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RESUMING) {
		struct e1000e_migration_file *migf;

		migf = e1000e_pci_resume_device_data(e1000e_dev);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		e1000e_dev->resuming_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_RESUMING && new == VFIO_DEVICE_STATE_STOP) {
		ret = e1000e_cmd_load_data(e1000e_dev, e1000e_dev->resuming_migf);
		if (ret)
			return ERR_PTR(ret);
		e1000e_disable_fds(e1000e_dev);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RUNNING) {
		e1000e_cmd_resume_device(e1000e_dev);
		return NULL;
	}

	/* vfio_mig_get_next_state() does not use arcs other than the above */
	WARN_ON(true);
	return ERR_PTR(-EINVAL);
}

static void e1000e_state_mutex_unlock(struct e1000e_pci_core_device *e1000e_dev)
{
again:
	spin_lock(&e1000e_dev->reset_lock);
	if (e1000e_dev->deferred_reset) {
		e1000e_dev->deferred_reset = false;
		spin_unlock(&e1000e_dev->reset_lock);
		e1000e_dev->mig_state = VFIO_DEVICE_STATE_RUNNING;
		e1000e_disable_fds(e1000e_dev);
		goto again;
	}
	mutex_unlock(&e1000e_dev->state_mutex);
	spin_unlock(&e1000e_dev->reset_lock);
}

static struct file *
e1000e_pci_set_device_state(struct vfio_device *vdev,
			    enum vfio_device_mig_state new_state)
{
	struct e1000e_pci_core_device *e1000e_dev = container_of(vdev,
				 struct e1000e_pci_core_device, core_device.vdev);
	enum vfio_device_mig_state next_state;
	struct file *res = NULL;
	int ret;

	mutex_lock(&e1000e_dev->state_mutex);
	while (new_state != e1000e_dev->mig_state) {
		ret = vfio_mig_get_next_state(vdev, e1000e_dev->mig_state,
					      new_state, &next_state);
		if (ret) {
			res = ERR_PTR(-EINVAL);
			break;
		}

		res = e1000e_pci_step_device_state_locked(e1000e_dev, next_state);
		if (IS_ERR(res))
			break;
		e1000e_dev->mig_state = next_state;
		if (WARN_ON(res && new_state != e1000e_dev->mig_state)) {
			fput(res);
			res = ERR_PTR(-EINVAL);
			break;
		}
	}
	e1000e_state_mutex_unlock(e1000e_dev);
	return res;
}

static int e1000e_pci_get_device_state(struct vfio_device *vdev,
				       enum vfio_device_mig_state *curr_state)
{
	struct e1000e_pci_core_device *e1000e_dev = container_of(
		vdev, struct e1000e_pci_core_device, core_device.vdev);

	mutex_lock(&e1000e_dev->state_mutex);
	*curr_state = e1000e_dev->mig_state;
	e1000e_state_mutex_unlock(e1000e_dev);
	return 0;
}

static int e1000e_pci_get_data_size(struct vfio_device *vdev,
				    unsigned long *stop_copy_length)
{
	struct e1000e_pci_core_device *e1000e_dev = container_of(
		vdev, struct e1000e_pci_core_device, core_device.vdev);
	struct pci_dev *pdev = to_pci_dev(vdev->dev);
	size_t state_size;
	int ret;

	mutex_lock(&e1000e_dev->state_mutex);
	ret = e1000e_cmd_query_data_size(e1000e_dev, &state_size);
	if (!ret)
		*stop_copy_length = state_size;
	e1000e_state_mutex_unlock(e1000e_dev);
	dev_dbg(&pdev->dev, "%s() -> size:%ld", __func__, state_size);
	return ret;
}

static int e1000e_pci_open_device(struct vfio_device *core_vdev)
{
	struct e1000e_pci_core_device *e1000e_dev = container_of(
		core_vdev, struct e1000e_pci_core_device, core_device.vdev);
	struct vfio_pci_core_device *core_device = &e1000e_dev->core_device;
	int ret;

	ret = vfio_pci_core_enable(core_device);
	if (ret)
		return ret;

	if (e1000e_dev->migrate_cap)
		e1000e_dev->mig_state = VFIO_DEVICE_STATE_RUNNING;

	vfio_pci_core_finish_enable(core_device);
	return 0;
}

static void e1000e_cmd_close_migratable(struct e1000e_pci_core_device *e1000e_dev)
{
	if (!e1000e_dev->migrate_cap)
		return;

	mutex_lock(&e1000e_dev->state_mutex);
	e1000e_disable_fds(e1000e_dev);
	e1000e_state_mutex_unlock(e1000e_dev);
}

static void e1000e_pci_close_device(struct vfio_device *core_vdev)
{
	struct e1000e_pci_core_device *e1000e_dev = container_of(
		core_vdev, struct e1000e_pci_core_device, core_device.vdev);

	e1000e_cmd_close_migratable(e1000e_dev);
	vfio_pci_core_close_device(core_vdev);
}

static bool e1000e_check_migration(struct pci_dev *pdev)
{
	return true; /* Yes, we can */
}

static const struct vfio_migration_ops e1000e_pci_mig_ops = {
	.migration_set_state = e1000e_pci_set_device_state,
	.migration_get_state = e1000e_pci_get_device_state,
	.migration_get_data_size = e1000e_pci_get_data_size,
};

static int e1000e_pci_dirty_enable(struct e1000e_pci_core_device *e1000e_dev,
				 struct rb_root_cached *ranges, u32 nnodes,
				 u64 *page_size)
{
	struct pci_dev *pdev = e1000e_dev->pdev;

	dev_dbg(&pdev->dev, "Start dirty page tracking\n");
	return 0;
}

static int e1000e_pci_dirty_disable(struct e1000e_pci_core_device *e1000e_dev)
{
	struct pci_dev *pdev = e1000e_dev->pdev;

	dev_dbg(&pdev->dev, "Start dirty page tracking\n");
	return 0;
}

static int e1000e_pci_dirty_sync(struct e1000e_pci_core_device *e1000e_dev,
				struct iova_bitmap *dirty_bitmap,
				unsigned long iova, unsigned long length)
{
	struct pci_dev *pdev = e1000e_dev->pdev;

	dev_dbg(&pdev->dev, "Start dirty page tracking\n");
	return 0;
}

static int e1000e_pci_dma_log_read_and_clear(struct vfio_device *core_vdev,
					    unsigned long iova, unsigned long length,
					    struct iova_bitmap *dirty)
{
	struct e1000e_pci_core_device *e1000e_dev =
		container_of(core_vdev, struct e1000e_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&e1000e_dev->state_mutex);
	ret = e1000e_pci_dirty_sync(e1000e_dev, dirty, iova, length);
	e1000e_state_mutex_unlock(e1000e_dev);

	return ret;
}

static int e1000e_pci_dma_log_start(struct vfio_device *core_vdev,
				      struct rb_root_cached *ranges, u32 nnodes,
				      u64 *page_size)
{
	struct e1000e_pci_core_device *e1000e_dev =
		container_of(core_vdev, struct e1000e_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&e1000e_dev->state_mutex);
	ret = e1000e_pci_dirty_enable(e1000e_dev, ranges, nnodes, page_size);
	e1000e_state_mutex_unlock(e1000e_dev);

	return ret;
}

static int e1000e_pci_dma_log_stop(struct vfio_device *core_vdev)
{
	struct e1000e_pci_core_device *e1000e_dev =
		container_of(core_vdev, struct e1000e_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&e1000e_dev->state_mutex);
	ret = e1000e_pci_dirty_disable(e1000e_dev);
	e1000e_state_mutex_unlock(e1000e_dev);

	return ret;
}

static const struct vfio_log_ops e1000e_pci_log_ops = {
	.log_start = e1000e_pci_dma_log_start,
	.log_stop = e1000e_pci_dma_log_stop,
	.log_read_and_clear = e1000e_pci_dma_log_read_and_clear,
};

static int e1000e_vfio_pci_init_dev(struct vfio_device *core_vdev)
{
	struct e1000e_pci_core_device *e1000e_dev = container_of(core_vdev,
				 struct e1000e_pci_core_device, core_device.vdev);
	struct pci_dev *pdev = to_pci_dev(core_vdev->dev);
	int ret = -1;

	if (!e1000e_check_migration(pdev))
		return ret;

	e1000e_dev->migrate_cap = 1;

	mutex_init(&e1000e_dev->state_mutex);
	spin_lock_init(&e1000e_dev->reset_lock);

	core_vdev->migration_flags = VFIO_MIGRATION_STOP_COPY;
	core_vdev->mig_ops = &e1000e_pci_mig_ops;
	core_vdev->log_ops = &e1000e_pci_log_ops;

	return vfio_pci_core_init_dev(core_vdev);
}


static const struct vfio_device_ops e1000e_vfio_pci_ops = {
	.name = "e1000e-vfio-pci",
	.init = e1000e_vfio_pci_init_dev,
	.release = vfio_pci_core_release_dev,
	.open_device = e1000e_pci_open_device,
	.close_device = e1000e_pci_close_device,
	.ioctl = vfio_pci_core_ioctl,
	.device_feature = vfio_pci_core_ioctl_feature,
	.read = vfio_pci_core_read,
	.write = vfio_pci_core_write,
	.mmap = vfio_pci_core_mmap,
	.request = vfio_pci_core_request,
	.match = vfio_pci_core_match,
	.bind_iommufd	= vfio_iommufd_physical_bind,
	.unbind_iommufd	= vfio_iommufd_physical_unbind,
	.attach_ioas	= vfio_iommufd_physical_attach_ioas,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	.detach_ioas	= vfio_iommufd_physical_detach_ioas,
#endif
};

static int e1000e_vfio_pci_probe(struct pci_dev *pdev,
				 const struct pci_device_id *id)
{
	struct e1000e_pci_core_device *e1000e_dev;
	int ret;

	e1000e_dev = vfio_alloc_device(e1000e_pci_core_device, core_device.vdev,
				  &pdev->dev, &e1000e_vfio_pci_ops);
	if (IS_ERR(e1000e_dev))
		return PTR_ERR(e1000e_dev);

	dev_set_drvdata(&pdev->dev, &e1000e_dev->core_device);
	e1000e_dev->pdev = pdev;

	ret = vfio_pci_core_register_device(&e1000e_dev->core_device);
	if (ret)
		goto out_put_vdev;
	return 0;

out_put_vdev:
	vfio_put_device(&e1000e_dev->core_device.vdev);
	return ret;
}

static void e1000e_vfio_pci_remove(struct pci_dev *pdev)
{
	struct e1000e_pci_core_device *e1000e_dev = e1000e_drvdata(pdev);

	vfio_pci_core_unregister_device(&e1000e_dev->core_device);
	vfio_put_device(&e1000e_dev->core_device.vdev);
}

static void e1000e_vfio_pci_aer_reset_done(struct pci_dev *pdev)
{
	struct e1000e_pci_core_device *e1000e_dev = e1000e_drvdata(pdev);

	if (!e1000e_dev->migrate_cap)
		return;

	/*
	 * As the higher VFIO layers are holding locks across reset and using
	 * those same locks with the mm_lock we need to prevent ABBA deadlock
	 * with the state_mutex and mm_lock.
	 * In case the state_mutex was taken already we defer the cleanup work
	 * to the unlock flow of the other running context.
	 */
	spin_lock(&e1000e_dev->reset_lock);
	e1000e_dev->deferred_reset = true;
	if (!mutex_trylock(&e1000e_dev->state_mutex)) {
		spin_unlock(&e1000e_dev->reset_lock);
		return;
	}
	spin_unlock(&e1000e_dev->reset_lock);
	e1000e_state_mutex_unlock(e1000e_dev);
}

static const struct pci_device_id e1000e_vfio_pci_table[] = {
	/* Intel Corporation 82574L Gigabit Network Connection */
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_INTEL, 0x10d3) },
	{}
};

MODULE_DEVICE_TABLE(pci, e1000e_vfio_pci_table);

static const struct pci_error_handlers e1000e_err_handlers = {
	.reset_done = e1000e_vfio_pci_aer_reset_done,
	.error_detected = vfio_pci_core_aer_err_detected,
};

static struct pci_driver e1000e_vfio_pci_driver = {
	.name = "e1000e-vfio-pci",
	.id_table = e1000e_vfio_pci_table,
	.probe = e1000e_vfio_pci_probe,
	.remove = e1000e_vfio_pci_remove,
	.err_handler = &e1000e_err_handlers,
	.driver_managed_dma = true,
};

module_pci_driver(e1000e_vfio_pci_driver);

MODULE_IMPORT_NS(IOMMUFD);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cédric Le Goater <clg@redhat.com>");
MODULE_DESCRIPTION("VFIO PCI - Intel Corporation E1000E");
