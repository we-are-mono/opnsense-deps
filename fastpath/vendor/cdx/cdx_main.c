/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

//uncomment to start dpa_app from cdx module
#define START_DPA_APP 1

#define DEFINE_GLOBALS
#include "portdefs.h"
#include "cdx.h"
#include "cdx_cmdhandler.h"
#include "dpa_ipsec.h"

static uint32_t init_level;
static cdx_deinit_func deinit_fn[MAX_CDX_INIT_FUNCTIONS];

void register_cdx_deinit_func(cdx_deinit_func func)
{
	if (init_level == MAX_CDX_INIT_FUNCTIONS) {
		printk("%s::cant register deinit function, increase MAX_CDX_INIT_FUNCTIONS\n", __FUNCTION__);
		return;
	}
	deinit_fn[init_level] = func;
	init_level++;
	return;
}

static void cdx_ctrl_deinit(void)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	mutex_lock(&ctrl->mutex);
	cdx_cmdhandler_exit();
	mutex_unlock(&ctrl->mutex);
}

static int __init cdx_ctrl_init(struct _cdx_info *cdx_info)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;
	int rc;

	mutex_init(&ctrl->mutex);
	spin_lock_init(&ctrl->lock);
	INIT_WORK(&ctrl->work, comcerto_fpp_workqueue);
	INIT_LIST_HEAD(&ctrl->msg_list);

	ctrl->dev = &cdx_info->dev;
	rc = cdx_ctrl_timer_init(ctrl);
	if (rc)
		goto error;
	mutex_lock(&ctrl->mutex);
	/* Initialize interface to fci */
	rc = cdx_cmdhandler_init();
	mutex_unlock(&ctrl->mutex);
	if (!rc)
		wake_up_process(ctrl->timer_thread);
	register_cdx_deinit_func(cdx_ctrl_deinit);
error:
	return rc;
}


#ifdef START_DPA_APP
static void cdx_free_modprobe_argv(struct subprocess_info *info)
{
	kfree(info->argv);
}


static int start_dpa_app(void)
{
	int retval;
	struct subprocess_info *info;
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};
	static char *modprobe_path = "/usr/bin/dpa_app";

	char **argv = kmalloc(sizeof(char *[3]), GFP_KERNEL);
	if (!argv)
		return -ENOMEM;

	argv[0] = modprobe_path;
	argv[1] = NULL;
	retval = 0;
	printk("%s::calling dpa_app argv %p\n", __FUNCTION__, argv);
	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
			NULL, cdx_free_modprobe_argv, NULL);
	if (info) {
		retval = call_usermodehelper_exec(info, (UMH_WAIT_PROC | UMH_KILLABLE));
	}
	return retval;
}
#endif

static void cdx_deinit_device(void)
{
	device_unregister(&cdx_info->dev);
	return;
}

/* This function is required by device_register(), do not remove */
static void cdx_dev_release(struct device *dev)
{
	return;
}

static int cdx_init_device(void)
{
	int rc;

	cdx_info->dev.init_name = "cdx";
	cdx_info->dev.release = cdx_dev_release;
	rc = device_register(&cdx_info->dev);
	if (rc != 0)
		printk("%s::device_register failed\n", __FUNCTION__);
	else
		register_cdx_deinit_func(cdx_deinit_device);
	return rc;
}

static void cdx_module_deinit(void)
{
	int ii = (init_level - 1);

	while(1) {
		if (deinit_fn[ii])
			deinit_fn[ii]();
		if (!ii)
			break;
		ii--;
	}
	kfree(cdx_info);
	return;
}

static int __init cdx_module_init(void)
{
	int rc = 0;
	int ii;

	printk(KERN_INFO "%s\n", __func__);

	for(ii = 0; ii < MAX_CDX_INIT_FUNCTIONS; ii++)
		deinit_fn[ii] = NULL;
	init_level = 0;

	cdx_info = kzalloc(sizeof(struct _cdx_info), GFP_KERNEL);
	if (!cdx_info)
	{
		printk(KERN_ERR "%s: Error allocating cdx_info structure\n", __func__);
		return (-ENOMEM);
	}
	rc = cdx_init_device();
	if (rc != 0) {
		printk("%s::cdx_init_device failed\n", __FUNCTION__);
		goto exit;
	}
	rc = cdx_ctrl_init(cdx_info);
	if (rc != 0) {
		printk("%s::cdx_ctrl_init failed\n", __FUNCTION__);
		goto exit;
	}
	rc = devman_init_linux_stats();
	if (rc != 0)  {
		printk("%s::devman_init call to register for linux stats failed\n", __FUNCTION__);
		goto exit;
	}
	rc = cdx_driver_init();
	if (rc != 0)  {
		printk("%s::cdx_driver_init failed\n", __FUNCTION__);
		goto exit;
	}
	/* creating a /proc/fqid_stats dir for listing fqids created by cdx module */
	cdx_init_fqid_procfs();
#ifdef START_DPA_APP
	rc = start_dpa_app();
	if (rc != 0)  {
		printk("%s::start_dpa_app failed rc %d\n", __FUNCTION__, rc);
		/* cant pass error code from start_dpa_app */
		rc = -EIO;
		goto exit;
	}
	printk("%s::start_dpa_app successful\n", __FUNCTION__);
#endif
#ifdef CFG_WIFI_OFFLOAD
	rc = dpaa_vwd_init();
	if (rc != 0)  {
		printk("%s::vwd_driver_init failed\n", __FUNCTION__);
		goto exit;
	}
#endif
	// initialize global fragmentation params
	if (cdx_init_frag_module()) { 
		printk("%s::cdx_init_frag_module failed\n", __FUNCTION__);
		rc = -EIO;
		goto exit;
	}

#ifdef DPA_IPSEC_OFFLOAD
	if (cdx_dpa_ipsec_init()) {
		printk("%s::dpa_ipsec start failed\n", __FUNCTION__);
		goto exit;
	}

	if (cdx_init_scatter_gather_bpool()) {
		printk("%s::cdx_init_scatter_gather_bpool failed\n",__FUNCTION__);
		rc = -ENOMEM;
		goto exit;
	}
	if (cdx_init_skb_2bfreed_bpool()) {
		printk("%s(%d) : cdx_init_skb_2bfreed_bpool failed\n", __FUNCTION__,__LINE__);
		rc = -ENOMEM;
		goto exit;
	}
#endif

#ifdef CDX_IP_REASSEMBLY
	printk("%s::calling cdx_init_ip_reassembly\n", __FUNCTION__);
	if (cdx_init_ip_reassembly()) {
		printk("%s::cdx_init_ip_reassembly failed\n", __FUNCTION__);
		rc = -EIO;
		goto exit;
	}
#endif // CDX_IP_REASSEMBLY

#ifdef CDX_TODO
	clk_put(clk_axi);
#endif
exit:
	if (rc) {
		printk("<<<<<<<<<<<<<<<<<<<< CDX module failed initialization >>>>>>>>>>>>>>>>>>>>>>>>>\n");
		cdx_module_deinit();
	}
	return rc;
}

static void __exit cdx_module_exit(void)
{
	printk(KERN_INFO "%s\n", __func__);
	cdx_module_deinit();
}

MODULE_LICENSE("GPL");
module_init(cdx_module_init);
module_exit(cdx_module_exit);
