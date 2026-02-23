/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef _UAPI_LINUX_EGM_H
#define _UAPI_LINUX_EGM_H

#include <linux/types.h>

#define EGM_TYPE ('E')

struct egm_retired_pages_info {
	__aligned_u64 offset;
	__aligned_u64 size;
};

struct egm_retired_pages_list {
	__u32 argsz;
	/* out */
	__u32 count;
	/* out */
	struct egm_retired_pages_info retired_pages[];
};

#define EGM_RETIRED_PAGES_LIST     _IO(EGM_TYPE, 100)

#endif /* _UAPI_LINUX_EGM_H */
