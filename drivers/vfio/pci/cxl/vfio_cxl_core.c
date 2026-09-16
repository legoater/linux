// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO support for CXL Type-2 devices.
 *
 * Copyright (c) 2026 NVIDIA Corporation & Affiliates
 */

#include <linux/module.h>
#include <linux/vfio_pci_core.h>

static int vfio_cxl_init_device(struct vfio_pci_core_device *vdev)
{
	return 0;
}

static void vfio_cxl_release_device(struct vfio_pci_core_device *vdev)
{
}

static int vfio_cxl_open_device(struct vfio_pci_core_device *vdev)
{
	return 0;
}

static void vfio_cxl_close_device(struct vfio_pci_core_device *vdev)
{
}

static void vfio_cxl_reset_prepare(struct vfio_pci_core_device *vdev)
{
}

static void vfio_cxl_reset_done(struct vfio_pci_core_device *vdev)
{
}

static const struct vfio_cxl_ops vfio_cxl_ops = {
	.init		= vfio_cxl_init_device,
	.release	= vfio_cxl_release_device,
	.open_device	= vfio_cxl_open_device,
	.close_device	= vfio_cxl_close_device,
	.reset_prepare	= vfio_cxl_reset_prepare,
	.reset_done	= vfio_cxl_reset_done,
	.owner		= THIS_MODULE,
};

static int __init vfio_cxl_init(void)
{
	return vfio_pci_core_register_cxl_ops(&vfio_cxl_ops);
}

static void __exit vfio_cxl_exit(void)
{
	vfio_pci_core_unregister_cxl_ops(&vfio_cxl_ops);
}

module_init(vfio_cxl_init);
module_exit(vfio_cxl_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VFIO support for CXL Type-2 devices");
