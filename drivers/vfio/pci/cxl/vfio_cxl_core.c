// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO support for CXL Type-2 devices.
 *
 * Copyright (c) 2026 NVIDIA Corporation & Affiliates
 */

#include <linux/cleanup.h>
#include <linux/io.h>
#include <linux/memory-failure.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/range.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vfio_pci_core.h>
#include <cxl/cxl.h>
#include <cxl/pci.h>

/**
 * struct vfio_cxl_state - per-device state for a vfio-cxl device
 * @cxlds: CXL device state; kept first for devm_cxl_dev_state_create()
 * @cxlmd: memory device joined to the CXL topology at bind
 * @hpa_range: host physical range of the HDM region
 * @hdm_pfn_space: HDM-region pfn range registered with memory_failure()
 * @hdm_valid: true when host CPU access to the HDM range is safe; under memory_lock
 */
struct vfio_cxl_state {
	struct cxl_dev_state cxlds;
	struct cxl_memdev *cxlmd;
	struct range hpa_range;
	struct pfn_address_space hdm_pfn_space;
	bool hdm_valid;
};

static unsigned long vfio_cxl_mem_pgoff(struct vm_area_struct *vma,
					unsigned long addr)
{
	unsigned long mask = (1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1;

	return (vma->vm_pgoff & mask) + ((addr - vma->vm_start) >> PAGE_SHIFT);
}

static vm_fault_t vfio_cxl_mem_huge_fault(struct vm_fault *vmf,
					  unsigned int order)
{
	struct vm_area_struct *vma = vmf->vma;
	struct vfio_pci_core_device *vdev = vma->vm_private_data;
	struct vfio_cxl_state *cxl = vdev->cxl;
	unsigned long addr = ALIGN_DOWN(vmf->address, PAGE_SIZE << order);
	unsigned long pfn = PHYS_PFN(cxl->hpa_range.start) +
			    vfio_cxl_mem_pgoff(vma, addr);
	vm_fault_t ret = VM_FAULT_FALLBACK;

	if (is_aligned_for_order(vma, addr, pfn, order)) {
		scoped_guard(rwsem_read, &vdev->memory_lock) {
			/*
			 * Insert a PFN only for a known-good decoder whose
			 * media is ready and whose Memory-Space is enabled.
			 */
			if (__vfio_pci_memory_enabled(vdev) &&
			    cxl->hdm_valid && cxl->cxlds.media_ready)
				ret = vfio_pci_vmf_insert_pfn(vdev, vmf, pfn,
							      order);
			else
				ret = VM_FAULT_SIGBUS;
		}
	}

	return ret;
}

static vm_fault_t vfio_cxl_mem_fault(struct vm_fault *vmf)
{
	return vfio_cxl_mem_huge_fault(vmf, 0);
}

static const struct vm_operations_struct vfio_cxl_mem_vm_ops = {
	.fault = vfio_cxl_mem_fault,
#ifdef CONFIG_ARCH_SUPPORTS_HUGE_PFNMAP
	.huge_fault = vfio_cxl_mem_huge_fault,
#endif
};

static int vfio_cxl_mem_mmap(struct vfio_pci_core_device *vdev,
			     struct vfio_pci_region *region,
			     struct vm_area_struct *vma)
{
	unsigned long mask = (1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1;
	u64 req_start = (vma->vm_pgoff & mask) << PAGE_SHIFT;
	u64 req_len = vma->vm_end - vma->vm_start;

	if (req_start + req_len > region->size)
		return -EINVAL;

	/*
	 * CXL.mem is coherent memory, so leave the mapping write-back cacheable.
	 */
	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &vfio_cxl_mem_vm_ops;
	vma->vm_private_data = vdev;

	return 0;
}

static ssize_t vfio_cxl_mem_rw(struct vfio_pci_core_device *vdev,
			       char __user *buf, size_t count, loff_t *ppos,
			       bool iswrite)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	void *mem;
	ssize_t done;

	if (pos >= range_len(&cxl->hpa_range))
		return -EINVAL;
	count = min_t(size_t, count, range_len(&cxl->hpa_range) - pos);

	scoped_guard(rwsem_read, &vdev->memory_lock) {
		/*
		 * Same gate as the fault path: only touch the HDM range with
		 * the decoder in a known-good state AND Memory-Space enabled,
		 * or a host CPU access aborts as a fatal SError.
		 */
		if (!cxl->hdm_valid || !__vfio_pci_memory_enabled(vdev))
			return -EIO;

		mem = memremap(cxl->hpa_range.start + pos, count, MEMREMAP_WB);
		if (!mem)
			return -ENOMEM;
		if (iswrite)
			done = copy_from_user(mem, buf, count) ? -EFAULT : count;
		else
			done = copy_to_user(buf, mem, count) ? -EFAULT : count;
		memunmap(mem);
	}
	if (done > 0)
		*ppos += done;

	return done;
}

/*
 * The CXL regions carry no per-region state (region->data is the shared,
 * devm-managed vfio_cxl_state), so releasing a region is a no-op.
 */
static void vfio_cxl_region_release(struct vfio_pci_core_device *vdev,
				    struct vfio_pci_region *region)
{
}

static const struct vfio_pci_regops vfio_cxl_mem_regops = {
	.rw = vfio_cxl_mem_rw,
	.mmap = vfio_cxl_mem_mmap,
	.release = vfio_cxl_region_release,
};

/*
 * Map a poisoned HDM-region pfn back to the file offset of each user mapping so
 * memory_failure() can unmap it and signal the fd holder. The region is a
 * single linear range at hpa_range.start; recover the per-vma file offset the
 * same way the fault handler derived the pfn.
 */
static int vfio_cxl_pfn_to_vma_pgoff(struct vm_area_struct *vma,
				     unsigned long pfn, pgoff_t *pgoff)
{
	struct vfio_pci_core_device *vdev;
	struct vfio_cxl_state *cxl;
	pgoff_t vma_off, pfn_off;
	unsigned long start_pfn;

	if (vma->vm_ops != &vfio_cxl_mem_vm_ops)
		return -ENOENT;

	vdev = vma->vm_private_data;
	cxl = vdev->cxl;

	start_pfn = PHYS_PFN(cxl->hpa_range.start);
	if (pfn < start_pfn ||
	    pfn >= start_pfn + (range_len(&cxl->hpa_range) >> PAGE_SHIFT))
		return -EFAULT;

	pfn_off = pfn - start_pfn;
	vma_off = vma->vm_pgoff &
		  ((1UL << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	/* Skip VMAs that do not map the pfn, e.g. a partial mmap of the region. */
	if (pfn_off < vma_off || pfn_off - vma_off >= vma_pages(vma))
		return -EFAULT;

	*pgoff = vma->vm_pgoff + (pfn_off - vma_off);
	return 0;
}

/*
 * The HDM region is struct-page-less device memory, so a memory error on it
 * cannot be routed through the normal page path. Register the range with
 * memory_failure() so such an error is contained to unmapping the range and a
 * SIGBUS to the fd holder instead of escalating to a host SError.
 */
static int vfio_cxl_register_pfn_space(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	unsigned long start_pfn = PHYS_PFN(cxl->hpa_range.start);

	cxl->hdm_pfn_space.node.start = start_pfn;
	cxl->hdm_pfn_space.node.last =
		start_pfn + (range_len(&cxl->hpa_range) >> PAGE_SHIFT) - 1;
	cxl->hdm_pfn_space.mapping = vdev->vdev.inode->i_mapping;
	cxl->hdm_pfn_space.pfn_to_vma_pgoff = vfio_cxl_pfn_to_vma_pgoff;

	return register_pfn_address_space(&cxl->hdm_pfn_space);
}

static void vfio_cxl_release_hpa(void *data)
{
	struct vfio_cxl_state *cxl = data;

	release_mem_region(cxl->hpa_range.start, range_len(&cxl->hpa_range));
}

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

	/*
	 * Claim the range IORESOURCE_EXCLUSIVE so no conflicting cacheable
	 * alias can fault the host once it is mapped write-back; there is no
	 * devm form, so pair it with a devm release action.
	 */
	if (!request_mem_region_exclusive(cxl->hpa_range.start,
					  range_len(&cxl->hpa_range),
					  "vfio-cxl-hdm")) {
		ret = -EBUSY;
		goto err;
	}
	ret = devm_add_action_or_reset(&pdev->dev, vfio_cxl_release_hpa, cxl);
	if (ret)
		goto err;

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

static int vfio_cxl_add_region(struct vfio_pci_core_device *vdev, u32 subtype,
			       const struct vfio_pci_regops *ops, size_t size,
			       u32 flags)
{
	u32 type = VFIO_REGION_TYPE_PCI_VENDOR_TYPE | PCI_VENDOR_ID_CXL;

	return vfio_pci_core_register_dev_region(vdev, type, subtype, ops,
						 size, flags, vdev->cxl);
}

static int vfio_cxl_open_device(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	int ret;

	/*
	 * vfio_pci_core_disable() frees all dynamic regions on close, so register
	 * them here per open rather than at bind. A failed first open never
	 * reaches close_device(), so unwind on error.
	 */
	ret = vfio_cxl_add_region(vdev, VFIO_REGION_SUBTYPE_CXL_MEM,
				  &vfio_cxl_mem_regops, range_len(&cxl->hpa_range),
				  VFIO_REGION_INFO_FLAG_READ |
				  VFIO_REGION_INFO_FLAG_WRITE |
				  VFIO_REGION_INFO_FLAG_MMAP);
	if (ret)
		return ret;

	/*
	 * The HDM region is advertised mmap-able, so a fd holder can fault its
	 * struct-page-less device memory in from the host CPU. Register it with
	 * memory_failure() to contain a memory error. -EOPNOTSUPP means
	 * CONFIG_MEMORY_FAILURE is off, so run without containment.
	 */
	ret = vfio_cxl_register_pfn_space(vdev);
	if (ret && ret != -EOPNOTSUPP)
		goto err_unregister_mem;

	/*
	 * The decoder is firmware-committed, so host access to the HDM range is
	 * safe. Open the access gate; reset and power transitions clear it until
	 * the decoder is restored.
	 */
	cxl->hdm_valid = true;

	return 0;

err_unregister_mem:
	vfio_pci_core_unregister_dev_region(vdev);

	return ret;
}

static void vfio_cxl_close_device(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;

	cxl->hdm_valid = false;
	unregister_pfn_address_space(&cxl->hdm_pfn_space);
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
