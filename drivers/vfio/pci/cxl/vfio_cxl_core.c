// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO support for CXL Type-2 devices.
 *
 * Copyright (c) 2026 NVIDIA Corporation & Affiliates
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/range.h>
#include <linux/vfio_pci_core.h>
#include <cxl/cxl.h>
#include <cxl/pci.h>

/**
 * struct vfio_cxl_state - per-device state for a vfio-cxl device
 * @cxlds: CXL device state; kept first for devm_cxl_dev_state_create()
 * @cxlmd: memory device joined to the CXL topology at bind
 * @hpa_range: host physical range of the HDM region
 */
struct vfio_cxl_state {
	struct cxl_dev_state cxlds;
	struct cxl_memdev *cxlmd;
	struct range hpa_range;
};

static int vfio_cxl_init_device(struct vfio_pci_core_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	struct vfio_cxl_state *cxl;
	struct cxl_memdev *cxlmd;
	u64 hdm_size, serial;
	u16 dvsec;
	int ret;

	/*
	 * pdev->hdm is cached at PCI enumeration, before any driver binds, so a
	 * device without it has no usable HDM decoder. Fall back to plain
	 * vfio-pci rather than deferring the bind forever.
	 */
	if (!pdev->hdm)
		return -ENODEV;

	/* The guest drives one virtual decoder; multiple are unsupported. */
	if (pdev->hdm->decoder_count != 1)
		return -EOPNOTSUPP;

	/* An interleaved decoder cannot be mapped 1:1 to the guest. */
	if (pdev->hdm->settings[0].interleave_ways != 1)
		return -EOPNOTSUPP;

	/*
	 * The guest drives resets through the CXL Device DVSEC and polls the
	 * shadow for completion. If the host cannot service a function-scoped
	 * CXL reset, that request could never complete, so refuse the device
	 * rather than advertise a reset the guest would poll on forever.
	 */
	if (!cxl_reset_capable(pdev))
		return -EOPNOTSUPP;

	hdm_size = range_len(&pdev->hdm->settings[0].hpa_range);
	if (!hdm_size)
		return -ENXIO;

	dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	serial = pci_get_dsn(pdev);

	/*
	 * Group the CXL-core allocations so a later failure unwinds them here.
	 * A failed init falls back to plain vfio-pci with the device still
	 * bound, so devm would otherwise hold them until unbind.
	 */
	if (!devres_open_group(&pdev->dev, NULL, GFP_KERNEL))
		return -ENOMEM;

	cxl = devm_cxl_dev_state_create(&pdev->dev, CXL_DEVTYPE_DEVMEM, serial,
					dvsec, struct vfio_cxl_state, cxlds,
					false);
	if (!cxl) {
		ret = -ENOMEM;
		goto err;
	}

	ret = cxl_pci_setup_regs(pdev, CXL_REGLOC_RBI_COMPONENT,
				 &cxl->cxlds.reg_map);
	if (ret) {
		pci_err(pdev, "vfio-cxl: no component registers\n");
		goto err;
	}

	/*
	 * vfio-pci-core requests the whole component-register BAR when the
	 * guest opens the device. Declare that BAR owned so the CXL core
	 * ioremaps the HDM and RAS sub-blocks without claiming them, and the
	 * full-BAR request does not collide.
	 */
	cxl_reg_map_add_owned_resource(&cxl->cxlds.reg_map,
				       pci_resource_n(pdev, pdev->hdm->hdm_bar));

	if (!cxl->cxlds.reg_map.component_map.hdm_decoder.valid) {
		pci_err(pdev, "vfio-cxl: HDM decoder registers not found\n");
		ret = -ENODEV;
		goto err;
	}

	/*
	 * A Type-2 accelerator has no mailbox and no media-ready register, so
	 * set media ready directly.
	 */
	cxl->cxlds.media_ready = true;

	ret = cxl_set_capacity(&cxl->cxlds, hdm_size);
	if (ret)
		goto err;

	cxlmd = devm_cxl_probe_mem(&cxl->cxlds, &cxl->hpa_range);
	if (IS_ERR(cxlmd)) {
		ret = PTR_ERR(cxlmd);
		goto err;
	}

	cxl->cxlmd = cxlmd;
	devres_close_group(&pdev->dev, NULL);

	/*
	 * Powering a CXL Type-2 function down and back up reinitializes its
	 * device state and discards the contents of its coherent memory. Pin
	 * it in D0 for as long as it is assigned so CXL.mem stays intact.
	 */
	vdev->disable_idle_d3 = true;
	vdev->cxl = cxl;

	return 0;

err:
	devres_release_group(&pdev->dev, NULL);
	return ret;
}

static void vfio_cxl_release_device(struct vfio_pci_core_device *vdev)
{
	vdev->cxl = NULL;
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
MODULE_IMPORT_NS("CXL");
