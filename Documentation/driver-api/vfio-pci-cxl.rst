.. SPDX-License-Identifier: GPL-2.0

=======================================
VFIO-PCI: CXL Type-2 device passthrough
=======================================

Overview
========

A CXL Type-2 device is an accelerator (for example a GPU) that exposes
host-managed device memory through an HDM decoder. vfio-pci alone does
not expose the HDM decoder registers or the CXL Device DVSEC, and it does
not place the device memory at a guest-chosen address.

The optional ``vfio-cxl`` module provides that. It is a provider for
vfio-pci-core, not a separate PCI driver. vfio-pci-core stays free of CXL
knowledge and loads ``vfio-cxl`` when it binds a CXL device.

Address model
=============

The HDM memory is a coherent host physical range (HPA). The host kernel
resolves that range before the guest sees the device, and owns it for the
bind lifetime. The guest only chooses where the memory appears in its own
physical address space (GPA), by programming a virtual endpoint HDM
decoder. The guest never reprograms the physical decoder.

The kernel holds the HPA and does not see the GPA. The guest programs a
GPA and does not see the HPA. The VMM holds the device fd, reads the
committed base from the decoder-register region described below, and maps
the HPA-backed HDM region at the GPA the guest committed. The base the
guest reads back is the GPA, not the HPA.

Driver model
============

There is no separate PCI driver. vfio-pci binds the device. During bind,
vfio-pci-core detects a CXL device (``pcie_is_cxl()``), loads ``vfio-cxl``
with ``request_module()``, and calls the registered ``struct
vfio_cxl_ops``. The module reference is pinned for the bind lifetime so
``vfio-cxl`` cannot unload while a device is bound.

At bind the provider creates the CXL memory device, takes ownership of the
whole component-register BAR, and (a Type-2 function has no mailbox) marks
the media ready directly. A non-CXL device, or a CXL device whose CXL
setup fails, falls back to the ordinary vfio-pci paths; the failure is not
fatal to the bind.

Regions
=======

``vfio-cxl`` adds two regions under the PCI vendor-type region
``VFIO_REGION_TYPE_PCI_VENDOR_TYPE`` for the CXL vendor (0x1e98):

``VFIO_REGION_SUBTYPE_CXL_MEM``
    The HDM memory region, backed by the fixed host physical range. It can
    be mapped with mmap. The fault handler inserts the host PFNs, including
    2 MB PMDs when the mapping is aligned, but only while the device is in
    a state where a host CPU access to the range is safe (Memory Space
    enabled, media ready, and the decoder not mid-reset); otherwise the
    fault takes ``SIGBUS``. The struct-page-less range is registered with
    the memory-failure machinery so a memory error can be contained. The
    VMM maps this region into guest memory at the committed GPA, and can
    also export it as a dma-buf (see below).

``VFIO_REGION_SUBTYPE_CXL_COMP_REGS``
    The HDM decoder registers. Access is read/write only (no mmap) and
    must be dword aligned; a misaligned or out-of-range access returns
    ``-EINVAL``. Reads are served live from the committed decoder. Guest
    writes are absorbed: the host already programmed and locked the
    physical decoder, so the register block is read-only to the guest and
    a write is dropped rather than forwarded. The region carries a
    ``VFIO_REGION_INFO_CAP_CXL_COMP_REGS`` capability that reports the
    component BAR and the offset of the decoder block within it, so the
    VMM can place the trapped window where the guest expects it.

The decoder register range is also excluded from the direct component-BAR
mmap and from host-side reads and writes: a kernel read of that range
through a mapping could abort on the fabric as a host SError, so reads
return ones and writes are dropped. The rest of the component BAR is a
normal vfio-pci BAR.

Guest decoder and commit
========================

The guest programs its virtual endpoint decoder through the trapped
region: it writes a base (a GPA), a size, and then the COMMIT bit. The
host already resolved and committed the physical placement before the
guest ran, so a live read of the decoder always shows COMMITTED and the
guest's commit poll completes. The physical decoder is never rewritten;
the guest's writes are absorbed.

The VMM observes the commit, reads the committed base, and maps the HDM
region at that GPA.

CXL Device DVSEC
================

The kernel virtualizes the CXL Device DVSEC body through the config-space
permission hooks. Reads and writes inside the DVSEC body use a per-open
shadow; a guest write stays in the shadow and does not reach hardware.
Accesses outside the DVSEC body go to the device as usual.

The self-clearing Control2 doorbells (Initiate CXL Reset and Initiate
Cache Write-Back and Invalidate) are never forwarded to hardware. The
kernel synthesizes their completion in the shadow so the guest poll
finishes, and runs the real operation at the vfio reset points (see
below).

DMA and iommufd
===============

A Type-2 accelerator issues ATS-translated DMA to addresses inside its own
HDM window, so that range must be present in the guest IOAS that backs the
nested stage-2 translation. The HDM range is struct-page-less coherent
memory, which a userspace-VA ``IOMMU_IOAS_MAP`` cannot pin.

The HDM memory region is therefore exportable as a dma-buf:
``VFIO_DEVICE_FEATURE_DMA_BUF`` on that region returns an fd that iommufd
maps with ``IOMMU_IOAS_MAP_FILE``, mapping the physical range without a VA
or a page pin. The dma-buf is revoked whenever the mapping is torn down
(reset, power transition, teardown), so a stale stage-2 mapping cannot
outlive the HDM window.

Reset
=====

A CXL Type-2 function must not take a Function Level Reset: an FLR resets
the coherent CXL.mem state and the HDM decoder. The PCI core reflects this
by preferring the CXL reset over FLR, so a function reset of a CXL device
runs the CXL DVSEC reset sequence, which resets the function and then
restores the HDM decoder and the PCI config state.

A guest requests a reset by writing Initiate CXL Reset in the DVSEC. That
write only stamps completion in the shadow. The real reset runs at the vfio
reset points (the reset ioctl and a virtualized FLR through config space):
the kernel zaps the HDM mapping and revokes the dma-buf, then runs the CXL
reset, which always clears the device memory, and restores and re-samples
the decoder afterwards. A CXL port masks Secondary Bus Reset by default, so a
``VFIO_DEVICE_PCI_HOT_RESET`` does not reach the endpoint and the HDM
state is untouched. If the port has SBR unmasked the reset can decommit
the decoder without restoring it, so the reset_done handler gates HDM
access; a ``VFIO_DEVICE_RESET`` then runs the CXL reset sequence and
restores it.

The decoder register region is served by live reads of the hardware
decoder with guest writes absorbed: the decoder is committed and locked by
the host, so a guest can neither decommit nor reprogram it, and the kernel
keeps no shadow of the decoder state. After a reset the kernel restores and
re-samples the firmware-committed decoder, so the geometry the guest reads
back is unchanged. A VMM that dropped its HDM mapping, for example across a
reset or a D3hot->D0 transition, must rescan the decoder and rebuild its
stage-2 mapping before it resumes HDM access.

UAPI
====

``VFIO_DEVICE_FLAGS_CXL``
    Set in ``VFIO_DEVICE_GET_INFO`` flags for a CXL Type-2 device.

``VFIO_REGION_TYPE_PCI_VENDOR_TYPE | 0x1e98`` with
``VFIO_REGION_SUBTYPE_CXL_MEM`` / ``VFIO_REGION_SUBTYPE_CXL_COMP_REGS``
    Reported through the region-info ``VFIO_REGION_INFO_CAP_TYPE``
    capability. Userspace finds each region by scanning for the type and
    subtype.

``VFIO_REGION_INFO_CAP_CXL_COMP_REGS``
    On the component-register region, reports the component BAR index and
    the decoder-block offset within it.

``VFIO_DEVICE_FEATURE_DMA_BUF``
    On the HDM memory region, returns a dma-buf fd for
    ``IOMMU_IOAS_MAP_FILE``.

The HDM decoder register layout is available to a VMM without a private
kernel header via ``uapi/cxl/cxl_regs.h``.

Scope
=====

This support covers a single, non-interleaved endpoint decoder on a
directly attached device. Multi-decoder devices, interleave, and
switch-attached topologies are not supported. The interfaces are
structured so those cases can be added later without changing the UAPI
described here.

A selftest, ``tools/testing/selftests/vfio/vfio_cxl_type2_test.c``,
exercises the interfaces above on a bound device.
