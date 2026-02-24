/*
 * CDX char device — FreeBSD port
 *
 * Replaces cdx_dev.c. Provides /dev/cdx_ctrl using FreeBSD cdevsw
 * instead of Linux register_chrdev/class_create/device_create.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/module.h>

#include "cdx.h"
#include "cdx_ioctl.h"
#include "misc.h"

static struct cdev *cdx_ctrl_cdev;
static volatile int cdx_ctrl_open_count;

/* Forward declarations for ioctl handlers (stubbed in cdx_dpa_stub.c) */
int cdx_ioc_set_dpa_params(unsigned long args);
int cdx_ioc_dpa_connadd(unsigned long args);
int cdx_ioc_create_mc_group(unsigned long args);
int cdx_ioc_add_member_to_group(unsigned long args);
int cdx_ioc_add_mcast_table_entry(unsigned long args);

static int
cdx_ctrl_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	/* Allow only one open instance */
	if (atomic_cmpset_int(&cdx_ctrl_open_count, 0, 1) == 0)
		return (EBUSY);
	return (0);
}

static int
cdx_ctrl_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	atomic_store_int(&cdx_ctrl_open_count, 0);
	return (0);
}

static int
cdx_ctrl_ioctl_fbsd(struct cdev *dev, u_long cmd, caddr_t addr,
    int fflag, struct thread *td)
{
	int retval;

	switch (cmd) {
	case CDX_CTRL_DPA_SET_PARAMS:
		retval = cdx_ioc_set_dpa_params((unsigned long)addr);
		break;

	case CDX_CTRL_DPA_CONNADD:
		retval = cdx_ioc_dpa_connadd((unsigned long)addr);
		break;

	case CDX_CTRL_DPA_QOS_CONFIG_ADD:
		retval = 0;
		break;

	case CDX_CTRL_DPA_ADD_MCAST_GROUP:
		retval = cdx_ioc_create_mc_group((unsigned long)addr);
		break;

	case CDX_CTRL_DPA_ADD_MCAST_MEMBER:
		retval = cdx_ioc_add_member_to_group((unsigned long)addr);
		break;

	case CDX_CTRL_DPA_ADD_MCAST_TABLE_ENTRY:
		retval = cdx_ioc_add_mcast_table_entry((unsigned long)addr);
		break;

	default:
		DPA_ERROR("unsupported ioctl cmd %lx\n", cmd);
		retval = EINVAL;
		break;
	}

	return (retval);
}

static struct cdevsw cdx_ctrl_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	D_TRACKCLOSE,
	.d_open =	cdx_ctrl_open,
	.d_close =	cdx_ctrl_close,
	.d_ioctl =	cdx_ctrl_ioctl_fbsd,
	.d_name =	CDX_CTRL_CDEVNAME,
};

static void
cdx_driver_deinit(void)
{
	if (cdx_ctrl_cdev != NULL) {
		destroy_dev(cdx_ctrl_cdev);
		cdx_ctrl_cdev = NULL;
	}
}

int
cdx_driver_init(void)
{
	if (cdx_ctrl_cdev != NULL)
		return (0);

	cdx_ctrl_open_count = 0;

	cdx_ctrl_cdev = make_dev(&cdx_ctrl_cdevsw, 0,
	    UID_ROOT, GID_WHEEL, 0600, CDX_CTRL_CDEVNAME);
	if (cdx_ctrl_cdev == NULL) {
		DPA_ERROR("could not create /dev/%s\n", CDX_CTRL_CDEVNAME);
		return (-1);
	}

	register_cdx_deinit_func(cdx_driver_deinit);
	return (0);
}
