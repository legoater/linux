// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO PCI driver for Intel 82576 (igb) Virtual Functions
 *
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Author: Cédric Le Goater <clg@redhat.com>
 */

#include <linux/anon_inodes.h>
#include <linux/compat.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/io.h>
#include <linux/interval_tree.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

/*
 * Migration interface via DVSEC in the VF extended config space.
 * Should match QEMU's.
 */
#define IGB_MIG_DVSEC_ID		1
#define IGB_MIG_DVSEC_REV		1
#define IGB_MIG_DVSEC_MIN_LEN		0x24

/* Register offsets relative to DVSEC base */
#define IGB_MIG_CAPS			0x0C
#define IGB_MIG_CTRL			0x10
#define IGB_MIG_STATUS			0x14
#define IGB_MIG_BUF_ADDR_LO		0x18
#define IGB_MIG_BUF_ADDR_HI		0x1C
#define IGB_MIG_DATA_SIZE		0x20

/* CAPS register layout */
#define IGB_MIG_CAP_F_STATE		BIT(0)
#define IGB_MIG_CAP_F_DIRTY		BIT(1)
#define IGB_MIG_CAPS_MAX_RANGES_SHIFT	8
#define IGB_MIG_CAPS_MAX_RANGES_MASK	(0xfu << 8)
#define IGB_MIG_CAPS_PGSIZE_MASK	(0x1fu << 12)

/* CTRL register: cmd in [7:0], arg in [31:8] */
#define IGB_MIG_CMD_SET_STATE		1
#define IGB_MIG_CMD_SAVE		2
#define IGB_MIG_CMD_LOAD		3
#define IGB_MIG_CMD_DIRTY_ENABLE	4
#define IGB_MIG_CMD_DIRTY_DISABLE	5
#define IGB_MIG_CMD_DIRTY_QUERY		6
#define IGB_MIG_CMD_GET_STATS		7

/* STATUS register: state [7:0], error_code [15:8], quiesced [16] */
#define IGB_MIG_STATUS_STATE_MASK	0xff
#define IGB_MIG_STATUS_ERROR_CODE_SHIFT	8
#define IGB_MIG_STATUS_ERR_CODE(s)	(((s) >> IGB_MIG_STATUS_ERROR_CODE_SHIFT) & 0xff)
#define IGB_MIG_STATUS_QUIESCED		BIT(16)

/* Device state values */
#define IGB_MIG_STATE_ERROR		0
#define IGB_MIG_STATE_STOP		1
#define IGB_MIG_STATE_RUNNING		2
#define IGB_MIG_STATE_STOP_COPY		3
#define IGB_MIG_STATE_RESUMING		4
#define IGB_MIG_STATE_PRE_COPY		5

#define IGB_MIG_DIRTY_DEFAULT_PGSIZE	4096
#define IGB_MIG_QUIESCE_TIMEOUT_MS	1000
#define IGB_VF_STATE_MAX_SIZE		4096

/* DMA buffer for DIRTY_ENABLE command */
struct igb_mig_dirty_enable_req {
	__le32 len;
	__le32 flags;
	__le64 pgsize;
	__le64 range_iova;
	__le64 range_size;
	__le32 reserved[4];
};

/* DMA buffer for DIRTY_QUERY command */
struct igb_mig_dirty_query {
	__le32 len;
	__le32 flags;
	__le64 iova;
	__le64 size;
	__le32 bitmap_size;
	__le32 dirty_page_count;
	__le64 dma_writes;
	__le32 reserved[6];
	u8 bitmap[];
};

/* DMA buffer for GET_STATS command */
struct igb_mig_stats_resp {
	__le64 dma_writes;
	__le64 dma_bytes;
	__le32 dirty_pages_set;
	__le32 dirty_pages_cleared;
	__le32 dirty_page_count;
	__le32 dirty_query_count;
};

struct igb_pci_dirty_range {
	u64 iova;
	u64 size;
};

struct igb_migration_file {
	struct file *filp;
	/* Protects migration file data and state */
	struct mutex lock;
	bool disabled;
	u8 *mig_data;
	size_t size;
	struct igb_pci_core_device *igb_dev;
};

struct igb_pci_core_device {
	struct vfio_pci_core_device core_device;
	struct pci_dev *pdev;

	u8 dirty_tracking:1;
	int dvsec_pos;
	int dvsec_len;
	u32 state_max_size;
	/* protect migration state */
	struct mutex state_mutex;
	enum vfio_device_mig_state mig_state;
	struct igb_migration_file *resuming_migf;
	struct igb_migration_file *saving_migf;
	struct igb_mig_dirty_query *dirty_query;
	size_t dirty_query_size;
	struct igb_pci_dirty_range *dirty_ranges;
	u8 max_dirty_ranges;
	u32 supported_pgsizes;
	u8 num_dirty_ranges;
	u64 dirty_page_size;
#ifdef CONFIG_VFIO_DEBUGFS
	struct dentry *debug_root;
#endif
};

static struct pci_dev *igb_to_pci_dev(struct igb_pci_core_device *igb_dev)
{
	return igb_dev->pdev;
}

static void igb_dvsec_set_buf_addr(struct igb_pci_core_device *igb_dev, phys_addr_t addr)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);

	pci_write_config_dword(pdev, igb_dev->dvsec_pos + IGB_MIG_BUF_ADDR_LO,
			       lower_32_bits(addr));
	pci_write_config_dword(pdev, igb_dev->dvsec_pos + IGB_MIG_BUF_ADDR_HI,
			       upper_32_bits(addr));
}

static int igb_dvsec_read(struct igb_pci_core_device *igb_dev, int pos, u32 *val)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	int ret;

	ret = pci_read_config_dword(pdev, igb_dev->dvsec_pos + pos, val);
	if (ret)
		return pcibios_err_to_errno(ret);
	if (PCI_POSSIBLE_ERROR(*val))
		return -EIO;
	return 0;
}

static int igb_get_state(struct igb_pci_core_device *igb_dev, u32 *state)
{
	u32 status;
	int ret;

	ret = igb_dvsec_read(igb_dev, IGB_MIG_STATUS, &status);
	if (ret)
		return ret;

	*state = status & IGB_MIG_STATUS_STATE_MASK;
	return 0;
}

static int igb_dvsec_send_cmd(struct igb_pci_core_device *igb_dev, u32 cmd)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	u32 status;
	int ret;

	pci_write_config_dword(pdev, igb_dev->dvsec_pos + IGB_MIG_CTRL, cmd);
	ret = igb_dvsec_read(igb_dev, IGB_MIG_STATUS, &status);
	if (ret) {
		dev_err(&pdev->dev,
			"DVSEC cmd 0x%x config read failed\n", cmd & 0xff);
		return ret;
	}
	if (IGB_MIG_STATUS_ERR_CODE(status)) {
		dev_err(&pdev->dev,
			"DVSEC cmd 0x%x failed (error %u)\n",
			cmd & 0xff, IGB_MIG_STATUS_ERR_CODE(status));
		return -EIO;
	}
	return 0;
}

static u32 igb_dvsec_read_status(struct igb_pci_core_device *igb_dev)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	u32 status;

	pci_read_config_dword(pdev, igb_dev->dvsec_pos + IGB_MIG_STATUS, &status);
	return status;
}

static int igb_wait_quiesced(struct igb_pci_core_device *igb_dev)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	u32 status;
	int ret;

	ret = read_poll_timeout(igb_dvsec_read_status, status,
				!PCI_POSSIBLE_ERROR(status) &&
				(status & IGB_MIG_STATUS_QUIESCED),
				100, IGB_MIG_QUIESCE_TIMEOUT_MS * 1000,
				false, igb_dev);
	if (ret || PCI_POSSIBLE_ERROR(status)) {
		dev_err(&pdev->dev,
			"device not quiesced (status 0x%x)\n", status);
		return ret ?: -EIO;
	}
	return 0;
}

static int igb_set_state(struct igb_pci_core_device *igb_dev, u32 state)
{
	return igb_dvsec_send_cmd(igb_dev,
			      IGB_MIG_CMD_SET_STATE | (state << 8));
}

static int igb_load_data(struct igb_pci_core_device *igb_dev,
			 struct igb_migration_file *migf)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	void *dma_buf;
	int ret;

	if (!migf->size)
		return 0;

	if (migf->size > igb_dev->state_max_size) {
		dev_err(&pdev->dev, "state too large (%zu)\n", migf->size);
		return -ENOSPC;
	}

	dma_buf = kzalloc(migf->size, GFP_KERNEL);
	if (!dma_buf)
		return -ENOMEM;

	memcpy(dma_buf, migf->mig_data, migf->size);

	igb_dvsec_set_buf_addr(igb_dev, virt_to_phys(dma_buf));
	ret = igb_dvsec_send_cmd(igb_dev,
			     IGB_MIG_CMD_LOAD | ((u32)migf->size << 8));

	kfree(dma_buf);

	if (!ret)
		dev_dbg(&pdev->dev, "loaded state: %zu bytes\n", migf->size);
	return ret;
}

static int igb_save_data(struct igb_pci_core_device *igb_dev,
			 void *buffer, size_t buffer_len)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	void *dma_buf;
	int ret;

	dma_buf = kzalloc(buffer_len, GFP_KERNEL);
	if (!dma_buf)
		return -ENOMEM;

	igb_dvsec_set_buf_addr(igb_dev, virt_to_phys(dma_buf));
	ret = igb_dvsec_send_cmd(igb_dev, IGB_MIG_CMD_SAVE);

	if (ret) {
		kfree(dma_buf);
		return ret;
	}

	memcpy(buffer, dma_buf, buffer_len);
	kfree(dma_buf);
	dev_dbg(&pdev->dev, "saved state: %zu bytes\n", buffer_len);
	return 0;
}

static struct igb_pci_core_device *igb_drvdata(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

	return container_of(core_device, struct igb_pci_core_device, core_device);
}

static int igb_validate_dvsec_header(struct igb_pci_core_device *igb_dev)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	u32 hdr;
	int ret;

	ret = igb_dvsec_read(igb_dev, PCI_DVSEC_HEADER1, &hdr);
	if (ret)
		return ret;

	if (PCI_DVSEC_HEADER1_REV(hdr) != IGB_MIG_DVSEC_REV) {
		dev_err(&pdev->dev, "unsupported DVSEC revision %u\n",
			PCI_DVSEC_HEADER1_REV(hdr));
		return -EINVAL;
	}

	if (PCI_DVSEC_HEADER1_LEN(hdr) < IGB_MIG_DVSEC_MIN_LEN) {
		dev_err(&pdev->dev, "DVSEC too short (%u, need %u)\n",
			PCI_DVSEC_HEADER1_LEN(hdr), IGB_MIG_DVSEC_MIN_LEN);
		return -EINVAL;
	}

	igb_dev->dvsec_len = PCI_DVSEC_HEADER1_LEN(hdr);
	return 0;
}

/*
 * Ensure the DVSEC state machine is RUNNING. Reads the current state
 * and cycles through STOP -> RUNNING if needed. No-op if already RUNNING.
 */
static int igb_pci_activate_dvsec(struct igb_pci_core_device *igb_dev)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	u32 state;
	int ret;

	ret = igb_get_state(igb_dev, &state);
	if (ret) {
		dev_err(&pdev->dev, "failed to read DVSEC state: %d\n", ret);
		return ret;
	}
	if (state == IGB_MIG_STATE_RUNNING)
		return 0;

	dev_info(&pdev->dev, "DVSEC state %u, activating\n", state);

	if (state != IGB_MIG_STATE_STOP)
		ret = igb_set_state(igb_dev, IGB_MIG_STATE_STOP);
	if (!ret)
		ret = igb_set_state(igb_dev, IGB_MIG_STATE_RUNNING);

	return ret;
}

static int igb_discover_dvsec(struct igb_pci_core_device *igb_dev)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	u32 caps;
	int ret;

	ret = igb_validate_dvsec_header(igb_dev);
	if (ret)
		return ret;

	ret = igb_dvsec_read(igb_dev, IGB_MIG_CAPS, &caps);
	if (ret)
		return ret;

	if (!(caps & IGB_MIG_CAP_F_STATE)) {
		dev_err(&pdev->dev, "missing migration caps 0x%x\n", caps);
		return -EINVAL;
	}

	ret = igb_dvsec_read(igb_dev, IGB_MIG_DATA_SIZE, &igb_dev->state_max_size);
	if (ret)
		return ret;

	if (!igb_dev->state_max_size ||
	    igb_dev->state_max_size > IGB_VF_STATE_MAX_SIZE) {
		dev_err(&pdev->dev, "invalid DATA_SIZE %u\n",
			igb_dev->state_max_size);
		return -EINVAL;
	}

	dev_info(&pdev->dev, "migration DVSEC at 0x%x: caps=0x%x data_size=%u\n",
		 igb_dev->dvsec_pos, caps, igb_dev->state_max_size);

	if (!(caps & IGB_MIG_CAP_F_DIRTY))
		return 0;

	igb_dev->max_dirty_ranges = (caps & IGB_MIG_CAPS_MAX_RANGES_MASK)
				     >> IGB_MIG_CAPS_MAX_RANGES_SHIFT;
	igb_dev->supported_pgsizes = caps & IGB_MIG_CAPS_PGSIZE_MASK;

	if (!igb_dev->max_dirty_ranges || !igb_dev->supported_pgsizes) {
		dev_warn(&pdev->dev,
			 "F_DIRTY set but max_ranges=%u pgsizes=0x%x, dirty tracking disabled\n",
			 igb_dev->max_dirty_ranges, igb_dev->supported_pgsizes);
		igb_dev->max_dirty_ranges = 0;
		return 0;
	}

	igb_dev->dirty_ranges = kzalloc_objs(*igb_dev->dirty_ranges,
					     igb_dev->max_dirty_ranges,
					     GFP_KERNEL);
	if (!igb_dev->dirty_ranges)
		return -ENOMEM;

	dev_dbg(&pdev->dev, "dirty caps: max_ranges=%u pgsizes=0x%x\n",
		igb_dev->max_dirty_ranges, igb_dev->supported_pgsizes);

	return 0;
}

static void igb_disable_fd(struct igb_migration_file *migf)
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

static int igb_release_file(struct inode *inode, struct file *filp)
{
	struct igb_migration_file *migf = filp->private_data;

	igb_disable_fd(migf);
	mutex_destroy(&migf->lock);
	kfree(migf);
	return 0;
}

static ssize_t igb_save_read(struct file *filp, char __user *buf, size_t len, loff_t *pos)
{
	struct igb_migration_file *migf = filp->private_data;
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
		done = -ENODEV;
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

static long igb_precopy_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct igb_migration_file *migf = filp->private_data;
	struct igb_pci_core_device *igb_dev = migf->igb_dev;
	struct vfio_precopy_info info = {};
	loff_t *pos = &filp->f_pos;
	int ret = 0;

	ret = vfio_check_precopy_ioctl(&igb_dev->core_device.vdev, cmd, arg, &info);
	if (ret)
		return ret;

	mutex_lock(&igb_dev->state_mutex);
	if (igb_dev->mig_state != VFIO_DEVICE_STATE_PRE_COPY) {
		mutex_unlock(&igb_dev->state_mutex);
		return -EINVAL;
	}

	mutex_lock(&migf->lock);
	if (migf->disabled) {
		ret = -ENODEV;
		goto out;
	}
	if (*pos > migf->size) {
		ret = -EINVAL;
		goto out;
	}
	info.initial_bytes = migf->size - *pos;
out:
	mutex_unlock(&migf->lock);
	mutex_unlock(&igb_dev->state_mutex);
	if (ret)
		return ret;
	return copy_to_user((void __user *)arg, &info,
			    offsetofend(struct vfio_precopy_info, dirty_bytes)) ? -EFAULT : 0;
}

static const struct file_operations igb_save_fops = {
	.owner = THIS_MODULE,
	.read = igb_save_read,
	.unlocked_ioctl = igb_precopy_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.release = igb_release_file,
};

static ssize_t igb_resume_write(struct file *filp, const char __user *buf,
				size_t len, loff_t *pos)
{
	struct igb_migration_file *migf = filp->private_data;
	loff_t requested_length;
	ssize_t done = 0;
	int ret;

	if (pos)
		return -ESPIPE;
	pos = &filp->f_pos;

	if (*pos < 0 || check_add_overflow((loff_t)len, *pos, &requested_length))
		return -EINVAL;

	if (requested_length > migf->igb_dev->state_max_size)
		return -EFBIG;
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

static const struct file_operations igb_resume_fops = {
	.owner = THIS_MODULE,
	.write = igb_resume_write,
	.release = igb_release_file,
};

static void igb_disable_fds(struct igb_pci_core_device *igb_dev)
{
	if (igb_dev->resuming_migf) {
		igb_disable_fd(igb_dev->resuming_migf);
		fput(igb_dev->resuming_migf->filp);
		igb_dev->resuming_migf = NULL;
	}

	if (igb_dev->saving_migf) {
		igb_disable_fd(igb_dev->saving_migf);
		fput(igb_dev->saving_migf->filp);
		igb_dev->saving_migf = NULL;
	}
}

static struct igb_migration_file *
igb_pci_resume_device_data(struct igb_pci_core_device *igb_dev)
{
	struct igb_migration_file *migf;
	int ret;

	migf = kzalloc_obj(*migf, GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("igb_mig", &igb_resume_fops, migf, O_WRONLY);
	if (IS_ERR(migf->filp)) {
		int err = PTR_ERR(migf->filp);

		kfree(migf);
		return ERR_PTR(err);
	}
	stream_open(migf->filp->f_inode, migf->filp);
	mutex_init(&migf->lock);
	migf->igb_dev = igb_dev;

	migf->mig_data = kvzalloc(igb_dev->state_max_size, GFP_KERNEL);
	if (!migf->mig_data) {
		ret = -ENOMEM;
		goto out_free;
	}

	return migf;

out_free:
	fput(migf->filp);
	return ERR_PTR(ret);
}

static int igb_populate_save_file(struct igb_pci_core_device *igb_dev,
				  struct igb_migration_file *migf)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	u32 data_size;
	int ret;

	ret = igb_dvsec_read(igb_dev, IGB_MIG_DATA_SIZE, &data_size);
	if (ret)
		return ret;

	if (!data_size || data_size > igb_dev->state_max_size) {
		dev_err(&pdev->dev, "bad DATA_SIZE %u after STOP_COPY\n", data_size);
		return -EINVAL;
	}

	mutex_lock(&migf->lock);

	migf->mig_data = kvzalloc(data_size, GFP_KERNEL);
	if (!migf->mig_data) {
		mutex_unlock(&migf->lock);
		return -ENOMEM;
	}

	ret = igb_save_data(igb_dev, migf->mig_data, data_size);
	if (ret) {
		kvfree(migf->mig_data);
		migf->mig_data = NULL;
		mutex_unlock(&migf->lock);
		return ret;
	}

	migf->size = data_size;
	migf->filp->f_pos = 0;
	mutex_unlock(&migf->lock);

	dev_dbg(&pdev->dev, "populated save file: %zu bytes\n", migf->size);
	return 0;
}

static struct igb_migration_file *
igb_pci_save_device_data(struct igb_pci_core_device *igb_dev)
{
	struct igb_migration_file *migf;
	int ret;

	migf = kzalloc_obj(*migf, GFP_KERNEL);
	if (!migf)
		return ERR_PTR(-ENOMEM);

	migf->filp = anon_inode_getfile("igb_mig", &igb_save_fops, migf, O_RDONLY);
	if (IS_ERR(migf->filp)) {
		int err = PTR_ERR(migf->filp);

		kfree(migf);
		return ERR_PTR(err);
	}

	stream_open(migf->filp->f_inode, migf->filp);
	mutex_init(&migf->lock);
	migf->igb_dev = igb_dev;

	ret = igb_populate_save_file(igb_dev, migf);
	if (ret) {
		fput(migf->filp);
		return ERR_PTR(ret);
	}

	return migf;
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
	case VFIO_DEVICE_STATE_PRE_COPY:
		return "VFIO_DEVICE_STATE_PRE_COPY";
	case VFIO_DEVICE_STATE_PRE_COPY_P2P:
		return "VFIO_DEVICE_STATE_PRE_COPY_P2P";
	default:
		return "VFIO_DEVICE_STATE_INVALID";
	}
}

static struct file *
igb_pci_step_device_state_locked(struct igb_pci_core_device *igb_dev,
				 enum vfio_device_mig_state new)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	enum vfio_device_mig_state cur = igb_dev->mig_state;
	int ret;

	dev_dbg(&pdev->dev, "%s => %s\n", vfio_device_mig_state_str(cur),
		vfio_device_mig_state_str(new));

	if (cur == VFIO_DEVICE_STATE_RUNNING && new == VFIO_DEVICE_STATE_STOP) {
		ret = igb_set_state(igb_dev, IGB_MIG_STATE_STOP);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_STOP_COPY) {
		struct igb_migration_file *migf;

		ret = igb_wait_quiesced(igb_dev);
		if (ret)
			return ERR_PTR(ret);

		ret = igb_set_state(igb_dev, IGB_MIG_STATE_STOP_COPY);
		if (ret)
			return ERR_PTR(ret);
		migf = igb_pci_save_device_data(igb_dev);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		igb_dev->saving_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_STOP_COPY && new == VFIO_DEVICE_STATE_STOP) {
		igb_disable_fds(igb_dev);
		ret = igb_set_state(igb_dev, IGB_MIG_STATE_STOP);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RESUMING) {
		struct igb_migration_file *migf;

		ret = igb_set_state(igb_dev, IGB_MIG_STATE_RESUMING);
		if (ret)
			return ERR_PTR(ret);
		migf = igb_pci_resume_device_data(igb_dev);
		if (IS_ERR(migf))
			return ERR_CAST(migf);
		get_file(migf->filp);
		igb_dev->resuming_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_RESUMING && new == VFIO_DEVICE_STATE_STOP) {
		ret = igb_load_data(igb_dev, igb_dev->resuming_migf);
		if (ret)
			return ERR_PTR(ret);
		igb_disable_fds(igb_dev);
		ret = igb_set_state(igb_dev, IGB_MIG_STATE_STOP);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RUNNING) {
		ret = igb_set_state(igb_dev, IGB_MIG_STATE_RUNNING);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_RUNNING && new == VFIO_DEVICE_STATE_PRE_COPY) {
		struct igb_migration_file *migf;

		ret = igb_set_state(igb_dev, IGB_MIG_STATE_PRE_COPY);
		if (ret)
			return ERR_PTR(ret);
		/*
		 * Create an empty save file.  Full device state is deferred
		 * to the PRE_COPY -> STOP_COPY transition since device
		 * state is transient while the device is still running.
		 */
		migf = kzalloc_obj(*migf, GFP_KERNEL);
		if (!migf)
			return ERR_PTR(-ENOMEM);
		migf->filp = anon_inode_getfile("igb_mig", &igb_save_fops, migf, O_RDONLY);
		if (IS_ERR(migf->filp)) {
			int err = PTR_ERR(migf->filp);

			kfree(migf);
			return ERR_PTR(err);
		}
		stream_open(migf->filp->f_inode, migf->filp);
		mutex_init(&migf->lock);
		migf->igb_dev = igb_dev;

		get_file(migf->filp);
		igb_dev->saving_migf = migf;
		return migf->filp;
	}

	if (cur == VFIO_DEVICE_STATE_PRE_COPY && new == VFIO_DEVICE_STATE_STOP_COPY) {
		struct igb_migration_file *migf = igb_dev->saving_migf;

		if (!migf)
			return ERR_PTR(-EINVAL);

		ret = igb_set_state(igb_dev, IGB_MIG_STATE_STOP_COPY);
		if (ret)
			return ERR_PTR(ret);

		ret = igb_wait_quiesced(igb_dev);
		if (ret)
			return ERR_PTR(ret);

		/*
		 * Now that the device is quiesced, snapshot the full state
		 * into the existing save file.  Userspace reads from the
		 * same data_fd it got during PRE_COPY.
		 */
		ret = igb_populate_save_file(igb_dev, migf);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	if (cur == VFIO_DEVICE_STATE_PRE_COPY && new == VFIO_DEVICE_STATE_RUNNING) {
		igb_disable_fds(igb_dev);
		ret = igb_set_state(igb_dev, IGB_MIG_STATE_RUNNING);
		if (ret)
			return ERR_PTR(ret);
		return NULL;
	}

	WARN_ON(true);
	return ERR_PTR(-EINVAL);
}

static struct file *
igb_pci_set_device_state(struct vfio_device *vdev,
			 enum vfio_device_mig_state new_state)
{
	struct igb_pci_core_device *igb_dev =
		container_of(vdev, struct igb_pci_core_device, core_device.vdev);
	enum vfio_device_mig_state next_state;
	struct file *res = NULL;
	int ret;

	mutex_lock(&igb_dev->state_mutex);
	while (new_state != igb_dev->mig_state) {
		ret = vfio_mig_get_next_state(vdev, igb_dev->mig_state, new_state, &next_state);
		if (ret) {
			res = ERR_PTR(-EINVAL);
			break;
		}

		res = igb_pci_step_device_state_locked(igb_dev, next_state);
		if (IS_ERR(res))
			break;
		igb_dev->mig_state = next_state;

		/* A mid-path step should never return an fd */
		if (WARN_ON(res && new_state != igb_dev->mig_state)) {
			fput(res);
			res = ERR_PTR(-EINVAL);
			break;
		}
	}
	mutex_unlock(&igb_dev->state_mutex);
	return res;
}

static int igb_pci_get_device_state(struct vfio_device *vdev,
				    enum vfio_device_mig_state *curr_state)
{
	struct igb_pci_core_device *igb_dev =
		container_of(vdev, struct igb_pci_core_device, core_device.vdev);

	mutex_lock(&igb_dev->state_mutex);
	*curr_state = igb_dev->mig_state;
	mutex_unlock(&igb_dev->state_mutex);
	return 0;
}

static int igb_pci_get_data_size(struct vfio_device *vdev,
				 unsigned long *stop_copy_length)
{
	struct igb_pci_core_device *igb_dev =
		container_of(vdev, struct igb_pci_core_device, core_device.vdev);

	*stop_copy_length = igb_dev->state_max_size;
	return 0;
}

static const struct vfio_migration_ops igb_pci_mig_ops = {
	.migration_set_state = igb_pci_set_device_state,
	.migration_get_state = igb_pci_get_device_state,
	.migration_get_data_size = igb_pci_get_data_size,
};

static int igb_pci_open_device(struct vfio_device *core_vdev)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	struct vfio_pci_core_device *core_device = &igb_dev->core_device;
	int ret;

	ret = vfio_pci_core_enable(core_device);
	if (ret)
		return ret;

	/* Activate the DVSEC state machine if not already RUNNING */
	ret = igb_pci_activate_dvsec(igb_dev);
	if (ret) {
		vfio_pci_core_disable(core_device);
		return ret;
	}

	igb_dev->mig_state = VFIO_DEVICE_STATE_RUNNING;
	vfio_pci_core_finish_enable(core_device);
	return 0;
}

static int igb_pci_dirty_disable(struct igb_pci_core_device *igb_dev);

static void igb_close_migratable(struct igb_pci_core_device *igb_dev)
{
	mutex_lock(&igb_dev->state_mutex);
	igb_disable_fds(igb_dev);
	igb_pci_dirty_disable(igb_dev);
	mutex_unlock(&igb_dev->state_mutex);
}

static void igb_pci_close_device(struct vfio_device *core_vdev)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);

	igb_close_migratable(igb_dev);
	vfio_pci_core_close_device(core_vdev);
}

static void igb_vfio_pci_release_dev(struct vfio_device *core_vdev)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);

	kfree(igb_dev->dirty_ranges);
	mutex_destroy(&igb_dev->state_mutex);
	vfio_pci_core_release_dev(core_vdev);
}

static int igb_pci_dirty_enable(struct igb_pci_core_device *igb_dev,
				struct rb_root_cached *ranges, u32 nnodes,
				u64 *page_size)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	struct interval_tree_node *node;
	u32 num_ranges = nnodes;
	u64 max_range_size = 0;
	size_t alloc_size;
	int i, ret;

	if (igb_dev->dirty_tracking)
		return -EBUSY;

	if (!igb_dev->max_dirty_ranges)
		return -EOPNOTSUPP;

	if (num_ranges > igb_dev->max_dirty_ranges) {
		vfio_combine_iova_ranges(ranges, nnodes,
					 igb_dev->max_dirty_ranges);
		num_ranges = igb_dev->max_dirty_ranges;
	}

	/* Only 4K is supported today; negotiate when more sizes are added */
	*page_size = max_t(u64, *page_size, IGB_MIG_DIRTY_DEFAULT_PGSIZE);

	/*
	 * supported_pgsizes keeps the raw CAPS pgsize bits [16:12]
	 * which match page size values directly: bit 12 = 4K, bit 16
	 * = 64K, etc.
	 */
	if (!(igb_dev->supported_pgsizes & *page_size))
		return -EINVAL;
	igb_dev->dirty_page_size = *page_size;

	node = interval_tree_iter_first(ranges, 0, ULONG_MAX);
	for (i = 0; i < num_ranges && node; i++) {
		struct igb_mig_dirty_enable_req *req;
		u64 start = node->start;
		u64 size = node->last - node->start + 1;

		igb_dev->dirty_ranges[i].iova = start;
		igb_dev->dirty_ranges[i].size = size;

		if (size > max_range_size)
			max_range_size = size;

		req = kzalloc_obj(*req, GFP_KERNEL);
		if (!req) {
			ret = -ENOMEM;
			goto err_disable;
		}

		req->len = cpu_to_le32(sizeof(*req));
		req->flags = 0;
		req->pgsize = cpu_to_le64(*page_size);
		req->range_iova = cpu_to_le64(start);
		req->range_size = cpu_to_le64(size);

		igb_dvsec_set_buf_addr(igb_dev, virt_to_phys(req));
		ret = igb_dvsec_send_cmd(igb_dev, IGB_MIG_CMD_DIRTY_ENABLE);

		kfree(req);

		if (ret)
			goto err_disable;

		dev_dbg(&pdev->dev,
			"dirty range[%d]: iova=0x%llx size=0x%llx pgsize=%llu\n",
			i, start, size, (unsigned long long)*page_size);

		node = interval_tree_iter_next(node, 0, ULONG_MAX);
	}
	igb_dev->num_dirty_ranges = num_ranges;

	/*
	 * Allocate the bounce buffer for dirty queries.  Sized to hold
	 * the header plus a bitmap covering the largest range.
	 */
	alloc_size = sizeof(*igb_dev->dirty_query) +
		     DIV_ROUND_UP(max_range_size / *page_size, BITS_PER_BYTE);
	igb_dev->dirty_query = kzalloc(alloc_size, GFP_KERNEL);
	if (!igb_dev->dirty_query) {
		ret = -ENOMEM;
		goto err_disable;
	}
	igb_dev->dirty_query_size = alloc_size;

	igb_dev->dirty_tracking = true;
	dev_dbg(&pdev->dev, "start dirty page tracking\n");
	return 0;

err_disable:
	igb_dvsec_send_cmd(igb_dev, IGB_MIG_CMD_DIRTY_DISABLE);
	igb_dev->num_dirty_ranges = 0;
	return ret;
}

static int igb_pci_dirty_disable(struct igb_pci_core_device *igb_dev)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);

	if (!igb_dev->dirty_tracking)
		return 0;

	igb_dvsec_send_cmd(igb_dev, IGB_MIG_CMD_DIRTY_DISABLE);

	kfree(igb_dev->dirty_query);
	igb_dev->dirty_query = NULL;
	igb_dev->dirty_query_size = 0;

	igb_dev->num_dirty_ranges = 0;
	igb_dev->dirty_tracking = false;
	dev_dbg(&pdev->dev, "stop dirty page tracking\n");
	return 0;
}

static bool igb_pci_dirty_range_valid(struct igb_pci_core_device *igb_dev,
				      unsigned long iova, unsigned long length)
{
	int i;

	for (i = 0; i < igb_dev->num_dirty_ranges; i++) {
		struct igb_pci_dirty_range *r = &igb_dev->dirty_ranges[i];

		if (iova >= r->iova && iova + length <= r->iova + r->size)
			return true;
	}
	return false;
}

static int igb_pci_dirty_sync(struct igb_pci_core_device *igb_dev,
			      struct iova_bitmap *dirty_bitmap,
			      unsigned long iova, unsigned long length)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	u64 pgsize = igb_dev->dirty_page_size;
	struct igb_mig_dirty_query *query = igb_dev->dirty_query;
	unsigned long nbits;
	u32 bmp_bytes;
	u32 dirty_pages = 0, i;
	int ret;

	if (!igb_dev->dirty_tracking)
		return -EINVAL;

	if (!igb_pci_dirty_range_valid(igb_dev, iova, length)) {
		dev_err(&pdev->dev,
			"dirty sync outside tracked range: iova=0x%lx length=0x%lx\n",
			iova, length);
		return -EINVAL;
	}

	dev_dbg(&pdev->dev, "dirty_sync iova=0x%lx length=0x%lx\n", iova, length);

	nbits = length / pgsize;
	bmp_bytes = DIV_ROUND_UP(nbits, BITS_PER_BYTE);

	query->len = cpu_to_le32(sizeof(*query) + bmp_bytes);
	query->flags = 0;
	query->iova = cpu_to_le64(iova);
	query->size = cpu_to_le64(length);
	memset(query->bitmap, 0, bmp_bytes);

	igb_dvsec_set_buf_addr(igb_dev, virt_to_phys(igb_dev->dirty_query));
	ret = igb_dvsec_send_cmd(igb_dev, IGB_MIG_CMD_DIRTY_QUERY);
	if (ret)
		return ret;

	for_each_set_bit(i, (unsigned long *)query->bitmap, nbits) {
		unsigned long dirty_iova = iova + (unsigned long)i * pgsize;

		dirty_pages++;
		iova_bitmap_set(dirty_bitmap, dirty_iova, pgsize);
	}

	dev_dbg(&pdev->dev,
		"dirty sync iova=%lx size=%lu dirty_pages=%u/%u dma_writes=%llu\n",
		iova, length, dirty_pages,
		le32_to_cpu(query->dirty_page_count),
		le64_to_cpu(query->dma_writes));

	return 0;
}

static int igb_pci_dma_log_read_and_clear(struct vfio_device *core_vdev,
					  unsigned long iova,
					  unsigned long length,
					  struct iova_bitmap *dirty)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&igb_dev->state_mutex);
	ret = igb_pci_dirty_sync(igb_dev, dirty, iova, length);
	mutex_unlock(&igb_dev->state_mutex);
	return ret;
}

static int igb_pci_dma_log_start(struct vfio_device *core_vdev,
				 struct rb_root_cached *ranges, u32 nnodes,
				 u64 *page_size)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&igb_dev->state_mutex);
	ret = igb_pci_dirty_enable(igb_dev, ranges, nnodes, page_size);
	mutex_unlock(&igb_dev->state_mutex);
	return ret;
}

static int igb_pci_dma_log_stop(struct vfio_device *core_vdev)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	int ret;

	mutex_lock(&igb_dev->state_mutex);
	ret = igb_pci_dirty_disable(igb_dev);
	mutex_unlock(&igb_dev->state_mutex);
	return ret;
}

static const struct vfio_log_ops igb_pci_log_ops = {
	.log_start = igb_pci_dma_log_start,
	.log_stop = igb_pci_dma_log_stop,
	.log_read_and_clear = igb_pci_dma_log_read_and_clear,
};

#ifdef CONFIG_VFIO_DEBUGFS

static int igb_stats_show(struct seq_file *s, void *unused)
{
	struct igb_pci_core_device *igb_dev = s->private;
	struct igb_mig_stats_resp *stats;
	int ret;

	stats = kzalloc_obj(*stats, GFP_KERNEL);
	if (!stats)
		return -ENOMEM;

	mutex_lock(&igb_dev->state_mutex);

	igb_dvsec_set_buf_addr(igb_dev, virt_to_phys(stats));
	ret = igb_dvsec_send_cmd(igb_dev, IGB_MIG_CMD_GET_STATS);
	if (ret) {
		seq_puts(s, "GET_STATS command failed\n");
		goto out;
	}

	seq_printf(s, "dma_writes:       %llu\n",
		   le64_to_cpu(stats->dma_writes));
	seq_printf(s, "dma_bytes:        %llu\n",
		   le64_to_cpu(stats->dma_bytes));
	seq_printf(s, "dirty_pages_set:  %u\n",
		   le32_to_cpu(stats->dirty_pages_set));
	seq_printf(s, "dirty_pages_clr:  %u\n",
		   le32_to_cpu(stats->dirty_pages_cleared));
	seq_printf(s, "dirty_page_count: %u\n",
		   le32_to_cpu(stats->dirty_page_count));
	seq_printf(s, "dirty_query_cnt:  %u\n",
		   le32_to_cpu(stats->dirty_query_count));

out:
	kfree(stats);
	mutex_unlock(&igb_dev->state_mutex);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(igb_stats);

static void igb_debugfs_init(struct igb_pci_core_device *igb_dev)
{
	struct dentry *migration_dir;

	migration_dir = debugfs_lookup("migration",
				       igb_dev->core_device.vdev.debug_root);
	if (!migration_dir)
		return;

	igb_dev->debug_root = debugfs_create_dir("dirty", migration_dir);
	dput(migration_dir);

	debugfs_create_file("stats", 0444, igb_dev->debug_root,
			    igb_dev, &igb_stats_fops);
}

static void igb_debugfs_exit(struct igb_pci_core_device *igb_dev)
{
	debugfs_remove_recursive(igb_dev->debug_root);
	igb_dev->debug_root = NULL;
}

#else

static inline void igb_debugfs_init(struct igb_pci_core_device *igb_dev) {}
static inline void igb_debugfs_exit(struct igb_pci_core_device *igb_dev) {}

#endif /* CONFIG_VFIO_DEBUGFS */

static int igb_vfio_pci_init_dev(struct vfio_device *core_vdev)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	struct pci_dev *pdev = to_pci_dev(core_vdev->dev);
	int ret = -EINVAL;

	if (!pdev->is_virtfn) {
		dev_err(&pdev->dev, "not a VF\n");
		return ret;
	}

	igb_dev->dvsec_pos = pci_find_dvsec_capability(pdev,
						       PCI_VENDOR_ID_INTEL,
						       IGB_MIG_DVSEC_ID);
	if (!igb_dev->dvsec_pos) {
		dev_err(&pdev->dev, "no migration DVSEC found\n");
		return ret;
	}

	dev_dbg(&pdev->dev, "init: vf_id=%d dvsec_pos=0x%x\n",
		pci_iov_vf_id(pdev), igb_dev->dvsec_pos);

	/* The pci_dev is needed early in DVSEC discovery */
	igb_dev->pdev = pdev;

	ret = igb_discover_dvsec(igb_dev);
	if (ret)
		return ret;

	mutex_init(&igb_dev->state_mutex);

	core_vdev->migration_flags = VFIO_MIGRATION_STOP_COPY | VFIO_MIGRATION_PRE_COPY;
	core_vdev->mig_ops = &igb_pci_mig_ops;
	core_vdev->log_ops = &igb_pci_log_ops;
	return vfio_pci_core_init_dev(core_vdev);
}

static bool igb_pci_range_overlaps_dvsec(struct igb_pci_core_device *igb_dev,
					u64 pos, size_t count)
{
	u64 dvsec_end = igb_dev->dvsec_pos + igb_dev->dvsec_len;
	u64 end = pos + count;

	return igb_dev->dvsec_pos &&
	       pos < dvsec_end &&
	       end > igb_dev->dvsec_pos;
}

static ssize_t igb_pci_read(struct vfio_device *core_vdev,
			    char __user *buf, size_t count, loff_t *ppos)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	ssize_t ret;

	ret = vfio_pci_core_read(core_vdev, buf, count, ppos);
	if (ret <= 0)
		return ret;

	if (index != VFIO_PCI_CONFIG_REGION_INDEX)
		return ret;

	/*
	 * The IGB DVSEC is currently the last and only PCIe extended
	 * capability. Zeroing the complete capability, including its
	 * extended capability header, removes it from the guest view.
	 */
	if (igb_pci_range_overlaps_dvsec(igb_dev, pos, ret)) {
		u64 start = max_t(u64, pos, igb_dev->dvsec_pos);
		u64 end = min_t(u64, pos + ret,
				igb_dev->dvsec_pos + igb_dev->dvsec_len);

		if (clear_user(buf + (start - pos), end - start))
			return -EFAULT;
	}

	return ret;
}

static int igb_pci_reset_cleanup(struct igb_pci_core_device *igb_dev)
{
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	int ret;

	dev_dbg(&pdev->dev, "reset cleanup (mig_state=%d)\n", igb_dev->mig_state);

	mutex_lock(&igb_dev->state_mutex);
	igb_disable_fds(igb_dev);
	igb_pci_dirty_disable(igb_dev);

	/*
	 * FLR does not clear the DVSEC state preserved by the L0 VMM.
	 * Restore the DVSEC state machine to RUNNING after reset.
	 */
	ret = igb_pci_activate_dvsec(igb_dev);

	igb_dev->mig_state = ret ? VFIO_DEVICE_STATE_ERROR :
				   VFIO_DEVICE_STATE_RUNNING;
	mutex_unlock(&igb_dev->state_mutex);
	return ret;
}

static bool igb_pci_is_flr_write(struct pci_dev *pdev,
				 u64 pos, const char __user *buf,
				 size_t count)
{
	int devctl = pdev->pcie_cap + PCI_EXP_DEVCTL;
	__le16 val;

	if (pos > devctl || pos + count < devctl + sizeof(val))
		return false;

	if (copy_from_user(&val, buf + (devctl - pos), sizeof(val)))
		return false;

	return le16_to_cpu(val) & PCI_EXP_DEVCTL_BCR_FLR;
}

static ssize_t igb_pci_write(struct vfio_device *core_vdev, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	struct pci_dev *pdev = igb_to_pci_dev(igb_dev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	bool flr;
	ssize_t ret;

	/*
	 * The DVSEC is owned and managed by the L0 VMM. Ignore guest
	 * writes, so that the guest cannot alter the migration state
	 * maintained by the host.
	 */
	if (index == VFIO_PCI_CONFIG_REGION_INDEX &&
	    igb_pci_range_overlaps_dvsec(igb_dev, pos, count))
		return count;

	flr = (index == VFIO_PCI_CONFIG_REGION_INDEX &&
	       igb_pci_is_flr_write(pdev, pos, buf, count));

	ret = vfio_pci_core_write(core_vdev, buf, count, ppos);

	if (ret > 0 && flr) {
		if (igb_pci_reset_cleanup(igb_dev))
			dev_warn(&pdev->dev, "reset cleanup failed after FLR\n");
	}

	return ret;
}

static long igb_pci_ioctl(struct vfio_device *core_vdev, unsigned int cmd,
			  unsigned long arg)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	long ret;

	ret = vfio_pci_core_ioctl(core_vdev, cmd, arg);
	if (ret)
		return ret;

	switch (cmd) {
	case VFIO_DEVICE_RESET:
		return igb_pci_reset_cleanup(igb_dev);
	}

	return 0;
}

static const struct vfio_device_ops igb_vfio_pci_ops = {
	.name = "igb-vfio-pci",
	.init = igb_vfio_pci_init_dev,
	.release = igb_vfio_pci_release_dev,
	.open_device = igb_pci_open_device,
	.close_device = igb_pci_close_device,
	.ioctl = igb_pci_ioctl,
	.get_region_info_caps = vfio_pci_ioctl_get_region_info,
	.device_feature = vfio_pci_core_ioctl_feature,
	.read = igb_pci_read,
	.write = igb_pci_write,
	.mmap = vfio_pci_core_mmap,
	.request = vfio_pci_core_request,
	.match = vfio_pci_core_match,
	.match_token_uuid = vfio_pci_core_match_token_uuid,
	.bind_iommufd = vfio_iommufd_physical_bind,
	.unbind_iommufd	= vfio_iommufd_physical_unbind,
	.attach_ioas = vfio_iommufd_physical_attach_ioas,
	.detach_ioas = vfio_iommufd_physical_detach_ioas,
};

static int igb_vfio_pci_probe(struct pci_dev *pdev,
			      const struct pci_device_id *id)
{
	struct igb_pci_core_device *igb_dev;
	int ret;

	igb_dev = vfio_alloc_device(igb_pci_core_device, core_device.vdev,
				    &pdev->dev, &igb_vfio_pci_ops);
	if (IS_ERR(igb_dev))
		return PTR_ERR(igb_dev);

	dev_set_drvdata(&pdev->dev, &igb_dev->core_device);

	ret = vfio_pci_core_register_device(&igb_dev->core_device);
	if (ret)
		goto out_put_vdev;

	igb_debugfs_init(igb_dev);
	return 0;

out_put_vdev:
	vfio_put_device(&igb_dev->core_device.vdev);
	return ret;
}

static void igb_vfio_pci_remove(struct pci_dev *pdev)
{
	struct igb_pci_core_device *igb_dev = igb_drvdata(pdev);

	igb_debugfs_exit(igb_dev);
	vfio_pci_core_unregister_device(&igb_dev->core_device);
	vfio_put_device(&igb_dev->core_device.vdev);
}

static const struct pci_device_id igb_vfio_pci_table[] = {
	/* Intel Corporation 82576 Gigabit Network Connection */
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_INTEL, 0x10ca) },
	{}
};

MODULE_DEVICE_TABLE(pci, igb_vfio_pci_table);

static struct pci_driver igb_vfio_pci_driver = {
	.name = "igb-vfio-pci",
	.id_table = igb_vfio_pci_table,
	.probe = igb_vfio_pci_probe,
	.remove = igb_vfio_pci_remove,
	.driver_managed_dma = true,
};

module_pci_driver(igb_vfio_pci_driver);

MODULE_IMPORT_NS("IOMMUFD");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cédric Le Goater <clg@redhat.com>");
MODULE_DESCRIPTION("VFIO PCI - Intel 82576 Virtual Function");
