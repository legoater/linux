.. SPDX-License-Identifier: GPL-2.0

=========================================
VFIO PCI variant driver for Intel igb VFs
=========================================

Overview
--------

Live migration of VFIO-passthrough devices requires hardware with
migration support, which is scarce and hard to debug.  An emulated
device provides a fully controlled testbed for developing and
validating the software stack: variant driver, VFIO migration v2
framework, QEMU, libvirt.

The ``igb-vfio-pci`` driver is a VFIO PCI variant driver for Intel
82576 Virtual Functions (PCI device 0x10ca).  It extends the
``vfio-pci-core`` framework and implements the VFIO migration protocol
v2 with stop-copy and pre-copy support.  The target scenario is nested
virtualization::

  L0 QEMU
    igb PF with x-vf-migration=on
    +-- VFs with migration DVSEC

  L1 kernel
    igb-vfio-pci variant driver
    translates VFIO migration v2 ioctls -> DVSEC config writes

  L1 QEMU (stock, unmodified)
    vfio-pci device model, standard migration fd

  L2 guest
    standard igbvf driver, unaware of migration

The migration interface is exposed through a DVSEC in the VF extended
config space (see `DVSEC register layout`_ below), advertised by the
L0 QEMU emulated PF when ``x-vf-migration=on``.

All control is via PCI config space writes; commands are synchronous.
Dirty page tracking is controlled through DVSEC commands and a shared
DMA buffer for enable, query, and bitmap transfer.

Migration state machine::

  Saving   (source): RUNNING -> PRE_COPY -> STOP_COPY
  Resuming (target): RESUMING -> STOP -> RUNNING
  Abort    (source): PRE_COPY -> RUNNING

DVSEC register layout
---------------------

The DVSEC is at offset 0x160 in VF extended config space.

Standard PCIe headers::

  Offset  Size  Name            Description
  0x00    4     Ext cap header  cap_id=0x23, ver=1, next
  0x04    4     DVSEC header 1  len[31:20], rev[19:16], vendor_id[15:0]
  0x08    2     DVSEC header 2  DVSEC ID (1)
  0x0A    2     Reserved        Padding for DWORD alignment

Vendor-specific registers (relative to DVSEC base)::

  Offset  Name        R/W  Description
  0x0C    CAPS        RO   F_STATE[0], F_DIRTY[1], max_ranges[11:8], pgsize[16:12]
  0x10    CTRL        WO   Doorbell: cmd[7:0], arg[31:8]
  0x14    STATUS      RO   state[7:0], error_code[15:8], quiesced[16]
  0x18    BUF_ADDR_LO RW   DMA buffer GPA low 32 bits
  0x1C    BUF_ADDR_HI RW   DMA buffer GPA high 32 bits
  0x20    DATA_SIZE   RO   State blob size in bytes

CTRL commands::

  Value  Name           Arg            Description
  1      SET_STATE      target state   Transition device state
  2      SAVE           -              DMA-write state to buffer
  3      LOAD           data size      DMA-read state from buffer
  4      DIRTY_ENABLE   -              Enable dirty tracking (params in buf)
  5      DIRTY_DISABLE  -              Disable dirty tracking
  6      DIRTY_QUERY    -              Query dirty bitmap (params in buf)
  7      GET_STATS      -              DMA-write stats to buffer

DVSEC device states (internal numbering, not ``enum vfio_device_mig_state``
values; the driver translates between the two)::

  Value  Name       Description
  0      ERROR      Unrecoverable error (error_code in STATUS)
  1      STOP       Device quiesced, no DMA
  2      RUNNING    Normal operation
  3      STOP_COPY  Stopped, state available for DMA save
  4      RESUMING   Accepting state via DMA load
  5      PRE_COPY   Running with dirty tracking + state snapshots

See ``drivers/vfio/pci/igb/main.c`` for the complete DMA buffer
layouts, error codes, and stats response definitions.
