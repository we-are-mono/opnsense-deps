/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/* OS abstraction functions used by CDX control code */

#include "cdx.h"

HostMessage msg_buf;
static int msg_buf_used = 0;


HostMessage *msg_alloc(void)
{
	if (msg_buf_used)
	{
		printk(KERN_ERR "%s: failed\n", __func__);
		return NULL;
	}

	msg_buf_used = 1;

	return &msg_buf;
}

void msg_free(HostMessage *msg)
{
	if (!msg_buf_used)
		printk(KERN_ERR "%s: freing already free msg buffer\n", __func__);

	msg_buf_used = 0;
}

int msg_send(HostMessage *msg)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;
	int rc = -1;

	if (!ctrl->event_cb)
		goto out;

	if (ctrl->event_cb(msg->code, msg->length, msg->data) < 0)
		goto out;

	rc = 0;

out:
	msg_free(msg);

	return rc;
}


void *Heap_Alloc(int size)
{
	/* FIXME we may want to use dma API's and use non cacheable memory */
	return kmalloc(size, GFP_KERNEL);
}


void Heap_Free(void *p)
{
	kfree(p);
}
