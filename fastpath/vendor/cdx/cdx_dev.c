/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**     
 * @file                cdx_dev.c     
 * @description         cdx driver open,r,w,ioctl call implemnetations 
 */

#include <linux/device.h>
#include "linux/ioctl.h"
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fdtable.h>

#include "portdefs.h"
#include "misc.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "lnxwrp_fm.h"

static int cdx_ctrl_cdev_major = -1;
static struct class *cdx_ctrl_class;
static struct device *cdx_ctrl_dev;
static atomic_t cdx_ctrl_open_count;

int cdx_ctrl_open(struct inode *inode, struct file *filp);
int cdx_ctrl_release(struct inode *inode, struct file *filp);
long cdx_ctrl_ioctl(struct file *filp, unsigned int cmd,
                unsigned long args);
#ifdef CONFIG_COMPAT
long cdx_ctrl_compat_ioctl(struct file *filp, unsigned int cmd,
                unsigned long args);
#endif


/* cdx device file ops */
static const struct file_operations cdx_dev_fops = {
        .owner                  = THIS_MODULE,
        .open                   = cdx_ctrl_open,
        .unlocked_ioctl         = cdx_ctrl_ioctl,
#ifdef CONFIG_COMPAT
        .compat_ioctl           = cdx_ctrl_compat_ioctl,
#endif /* CONFIG_COMPAT */
        .release                = cdx_ctrl_release
};

int cdx_ctrl_open(struct inode *inode, struct file *filp)
{
	//DPA_INFO("%s::\n", __FUNCTION__);
	//allow only one open instance
	if (!atomic_dec_and_test(&cdx_ctrl_open_count)) {
		atomic_inc(&cdx_ctrl_open_count);
		return -EBUSY;
	}
	return 0;
}

int cdx_ctrl_release(struct inode *inode, struct file *filp)
{
	//release open instance
	//DPA_INFO("%s::\n", __FUNCTION__);
	//TBD - recover resources here
	atomic_inc(&cdx_ctrl_open_count);
	return 0;
}

#ifdef DPAA_DEBUG_ENABLE
extern void *get_muram_data(uint32_t *size);
static long cdx_get_muram_data(unsigned long args)
{
	long retval;
	uint8_t *pdata;
	uint32_t size;
	struct muram_data data_in;

	if(copy_from_user(&data_in, (void *)args,
				sizeof(struct muram_data))) {
		DPA_ERROR("%s::unable to copy struct get_muram_data\n", __FUNCTION__);
		return (-EIO);
	}
	pdata = get_muram_data(&size);
	if (!pdata) {
		DPA_ERROR("%s::get_muram_data failed\n", __FUNCTION__);
		return (-EIO);
	}
	if (size > data_in.size) {
		DPA_ERROR("%s::muram data size is %d,does not fit\n", __FUNCTION__, size);
		retval = -EINVAL;
		goto func_ret;
	}
	data_in.size = size;
	if(copy_to_user(data_in.buff, pdata, size)) {
		DPA_ERROR("%s::unable to copy muram data\n", __FUNCTION__);
		retval = -EIO;
		goto func_ret;
	}
	if (copy_to_user((void *)args, &data_in, sizeof(struct muram_data))) {
		DPA_ERROR("%s::unable to copy result\n", __FUNCTION__);
		retval = -EIO;
		goto func_ret;
	}
	retval = 0;
func_ret:
	kfree(pdata);
	return retval;
}
#endif

int disp_muram(void)
{
#ifdef DPAA_DEBUG_ENABLE
	int ii;
	uint8_t *pdata;
	uint32_t size;

	printk("%s::\n", __FUNCTION__);
	pdata = get_muram_data(&size);
	if (!pdata) {
		DPA_ERROR("%s::get_muram_data failed\n", __FUNCTION__);
		return (-EIO);
	}

	printk("%s::muram data size %d\n", __FUNCTION__, size);
	for (ii = 0; ii < size; ii++) {
		if (!(ii % 16))
			printk("\n%04x:%02x ", ii, *pdata);
		else
			printk("%02x ", *pdata);
		pdata++;
	}
#else
	printk("%s::\n", __FUNCTION__);
#endif
	return 0;
}


long cdx_ctrl_ioctl(struct file *filp, unsigned int cmd,
                unsigned long args) 
{
	int retval;

	//DPA_INFO("%s::cmd %d\n", __FUNCTION__, cmd);
	switch (cmd) {
		case CDX_CTRL_DPA_SET_PARAMS:
			retval = cdx_ioc_set_dpa_params(args);
			break;

		case CDX_CTRL_DPA_CONNADD:
			//test conection addition
			retval = cdx_ioc_dpa_connadd(args);
			break;

#ifdef DPAA_DEBUG_ENABLE
		case CDX_CTRL_DPA_GET_MURAM_DATA:
			//get muram contents
			retval = cdx_get_muram_data(args);
			break;
#endif

		case CDX_CTRL_DPA_QOS_CONFIG_ADD:
			printk("%s::cdx_ioc_dpa_configqos not called\n", __FUNCTION__);
			retval = 0;
			break;

		case CDX_CTRL_DPA_ADD_MCAST_GROUP:
			retval = cdx_ioc_create_mc_group(args);
			break;
		case CDX_CTRL_DPA_ADD_MCAST_MEMBER:
			retval = cdx_ioc_add_member_to_group(args);
			break;
		case CDX_CTRL_DPA_ADD_MCAST_TABLE_ENTRY:
			retval = cdx_ioc_add_mcast_table_entry(args);
			break;
		default:
			DPA_ERROR("%s::unsupported ioctl cmd %x\n", 
					__FUNCTION__, cmd);
			retval = -EINVAL;
			break;
	}
	return retval;
}

#ifdef CONFIG_COMPAT
long cdx_ctrl_compat_ioctl(struct file *filp, unsigned int cmd,
                unsigned long args)
{
	DPA_INFO("%s::\n", __FUNCTION__);
	return 0;
}
#endif

static void cdx_driver_deinit(void)
{
	device_destroy(cdx_ctrl_class, MKDEV(cdx_ctrl_cdev_major, 0));
	class_destroy(cdx_ctrl_class);
	unregister_chrdev(cdx_ctrl_cdev_major, CDX_CTRL_CLS_CDEVNAME);
	return;
}

int cdx_driver_init(void)
{
	/* Cannot initialize the wrapper twice */
	if (cdx_ctrl_cdev_major >= 0)
		return 0;

	//initialize driver usage count
	atomic_set(&cdx_ctrl_open_count, 1);
	cdx_ctrl_cdev_major = register_chrdev(0,CDX_CTRL_CDEVNAME,&cdx_dev_fops);
	if (cdx_ctrl_cdev_major < 0) {
		DPA_ERROR("%s::Could not register dev %s\n", 
				__FUNCTION__, CDX_CTRL_CDEVNAME);
		return -1;
	}

	cdx_ctrl_class = class_create(THIS_MODULE, CDX_CTRL_CLS_CDEVNAME);
	if (IS_ERR(cdx_ctrl_class)) {
		DPA_ERROR("%s::Failed to create %s class device\n",
				__FUNCTION__, CDX_CTRL_CLS_CDEVNAME);
		unregister_chrdev(cdx_ctrl_cdev_major, CDX_CTRL_CLS_CDEVNAME);
		cdx_ctrl_class = NULL;
		return -1;
	}

	cdx_ctrl_dev = device_create( cdx_ctrl_class,NULL,
			MKDEV(cdx_ctrl_cdev_major, 0),NULL,CDX_CTRL_CLS_CDEVNAME);
	if (IS_ERR(cdx_ctrl_dev)) {
		DPA_ERROR("%s::Failed to create %s device\n",
				__FUNCTION__, CDX_CTRL_CLS_CDEVNAME);
		class_destroy(cdx_ctrl_class);
		unregister_chrdev(cdx_ctrl_cdev_major, CDX_CTRL_CLS_CDEVNAME);
		cdx_ctrl_cdev_major = -1;
		return -1;
	}
	register_cdx_deinit_func(cdx_driver_deinit);
	return 0;
}



