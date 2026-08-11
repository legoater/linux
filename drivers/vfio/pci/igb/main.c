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

struct igb_pci_core_device {
	struct vfio_pci_core_device core_device;

	int dvsec_pos;
	u32 state_max_size;
	/* protect migration state */
	struct mutex state_mutex;
	enum vfio_device_mig_state mig_state;
};

static struct igb_pci_core_device *igb_drvdata(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

	return container_of(core_device, struct igb_pci_core_device, core_device);
}

static int igb_pci_open_device(struct vfio_device *core_vdev)
{
	struct igb_pci_core_device *igb_dev =
		container_of(core_vdev, struct igb_pci_core_device, core_device.vdev);
	struct vfio_pci_core_device *core_device = &igb_dev->core_device;
	int ret;

	ret = vfio_pci_core_enable(core_device);
	if (ret)
		return ret;

	igb_dev->mig_state = VFIO_DEVICE_STATE_RUNNING;
	vfio_pci_core_finish_enable(core_device);
	return 0;
}

static void igb_pci_close_device(struct vfio_device *core_vdev)
{
	vfio_pci_core_close_device(core_vdev);
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

	mutex_init(&igb_dev->state_mutex);

	return vfio_pci_core_init_dev(core_vdev);
}

static const struct vfio_device_ops igb_vfio_pci_ops = {
	.name = "igb-vfio-pci",
	.init = igb_vfio_pci_init_dev,
	.release = vfio_pci_core_release_dev,
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
