// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO PCI driver for Intel 82576 (igb) Virtual Functions
 *
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Author: Cédric Le Goater <clg@redhat.com>
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
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
#define IGB_MIG_DATA_SIZE		0x20

/* CAPS register layout */
#define IGB_MIG_CAP_F_STATE		BIT(0)

/* CTRL register: cmd in [7:0], arg in [31:8] */
#define IGB_MIG_CMD_SET_STATE		1

/* STATUS register: state [7:0], error_code [15:8], quiesced [16] */
#define IGB_MIG_STATUS_STATE_MASK	0xff
#define IGB_MIG_STATUS_ERROR_CODE_SHIFT	8
#define IGB_MIG_STATUS_ERR_CODE(s)	(((s) >> IGB_MIG_STATUS_ERROR_CODE_SHIFT) & 0xff)

/* Device state values */
#define IGB_MIG_STATE_ERROR		0
#define IGB_MIG_STATE_STOP		1
#define IGB_MIG_STATE_RUNNING		2
#define IGB_VF_STATE_MAX_SIZE		4096

struct igb_pci_core_device {
	struct vfio_pci_core_device core_device;
	struct pci_dev *pdev;

	int dvsec_pos;
	int dvsec_len;
	u32 state_max_size;
	/* protect migration state */
	struct mutex state_mutex;
	enum vfio_device_mig_state mig_state;
};

static struct pci_dev *igb_to_pci_dev(struct igb_pci_core_device *igb_dev)
{
	return igb_dev->pdev;
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

static int igb_set_state(struct igb_pci_core_device *igb_dev, u32 state)
{
	return igb_dvsec_send_cmd(igb_dev,
			      IGB_MIG_CMD_SET_STATE | (state << 8));
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

	return 0;
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

	if (cur == VFIO_DEVICE_STATE_STOP && new == VFIO_DEVICE_STATE_RUNNING) {
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

static void igb_pci_close_device(struct vfio_device *core_vdev)
{
	vfio_pci_core_close_device(core_vdev);
}

static void igb_vfio_pci_release_dev(struct vfio_device *core_vdev)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);

	mutex_destroy(&igb_dev->state_mutex);
	vfio_pci_core_release_dev(core_vdev);
}

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

	return vfio_pci_core_init_dev(core_vdev);
}

static const struct vfio_device_ops igb_vfio_pci_ops = {
	.name = "igb-vfio-pci",
	.init = igb_vfio_pci_init_dev,
	.release = igb_vfio_pci_release_dev,
	.open_device = igb_pci_open_device,
	.close_device = igb_pci_close_device,
	.ioctl = vfio_pci_core_ioctl,
	.get_region_info_caps = vfio_pci_ioctl_get_region_info,
	.device_feature = vfio_pci_core_ioctl_feature,
	.read = vfio_pci_core_read,
	.write = vfio_pci_core_write,
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

	return 0;

out_put_vdev:
	vfio_put_device(&igb_dev->core_device.vdev);
	return ret;
}

static void igb_vfio_pci_remove(struct pci_dev *pdev)
{
	struct igb_pci_core_device *igb_dev = igb_drvdata(pdev);

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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cédric Le Goater <clg@redhat.com>");
MODULE_DESCRIPTION("VFIO PCI - Intel 82576 Virtual Function");
