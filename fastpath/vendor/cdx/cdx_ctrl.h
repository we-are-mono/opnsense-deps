/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _CDX_CTRL_H_
#define _CDX_CTRL_H_

struct _cdx_ctrl {
	struct mutex mutex;
	spinlock_t lock;
	struct device *dev;
	struct task_struct *timer_thread;
	struct hlist_head *timer_inner_wheel;
	struct hlist_head *timer_outer_wheel;

	int (*event_cb)(u16, u16, u16*);

	struct list_head msg_list;
	struct work_struct work;	
};

struct _cdx_info {
	unsigned long ddr_phys_baseaddr;
	void *ddr_baseaddr;
	unsigned int ddr_size;
	void *cbus_baseaddr;
	void *apb_baseaddr;
	struct device dev;
	struct _cdx_ctrl ctrl;
};

extern struct _cdx_info *cdx_info;

/* used for asynchronous message transfer to CDX */
#define FPP_MAX_MSG_LENGTH	256 /* expressed in U8 -> 256 bytes*/
struct fpp_msg {
	struct list_head list;
	void (*callback)(unsigned long, int, u16, u16 *);
	unsigned long data;
	u16 fcode;
	u16 length;
	u16 *payload;
};

#endif /* _CDX_CTRL_H_ */
