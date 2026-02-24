/*
 *  Copyright 2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
//#include <linux/gfp.h>
//#include <linux/slab.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
//#include <net/if_inet6.h>
//#include <uapi/linux/in6.h> 
#include <linux/spinlock.h>
//#include <linux/if_arp.h>
#include "fm_vsp_ext.h"
#include "lnxwrp_fm.h"
#include <linux/fsl_oh_port.h>
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "mac.h"
#include "portdefs.h"
static struct dpa_bp *gs_dpa_vsp_bp;		/* VSP Buffer pool */

#define DPAA_VSP_MAX_BUF_COUNT 512

/* For all Buffer pools using the ethernet driver seed routine,
 * we'll be using the same   BPOOL size */
#define DPAA_VSP_BUF_SIZE dpa_bp_size(x)

static struct dpa_bp *dpa_vsp_bp_probe(struct net_device *net_dev)
{
	struct dpa_bp		*dpa_vsp_bp;
	dpa_vsp_bp = devm_kzalloc(net_dev->dev.parent, sizeof(*dpa_vsp_bp), GFP_KERNEL);
	if (unlikely(dpa_vsp_bp == NULL)) {
		dev_err(net_dev->dev.parent, "devm_kzalloc() failed\n");
		goto out;
	}

	dpa_vsp_bp->percpu_count = devm_alloc_percpu(net_dev->dev.parent, *dpa_vsp_bp->percpu_count);
	dpa_vsp_bp->config_count = DPAA_VSP_MAX_BUF_COUNT;
	dpa_vsp_bp->size = DPAA_VSP_BUF_SIZE;
	dpa_vsp_bp->seed_cb = dpa_bp_priv_seed;
	dpa_vsp_bp->free_buf_cb = _dpa_bp_free_pf;
	dpa_vsp_bp->dev = net_dev->dev.parent;
	if (dpa_bp_alloc(dpa_vsp_bp, dpa_vsp_bp->dev)) {
		dev_err(net_dev->dev.parent,"%s::dpa_bp_alloc failed for VSP\n", __FUNCTION__);
		devm_kfree(net_dev->dev.parent,dpa_vsp_bp);
		goto out;
	}
	gs_dpa_vsp_bp = dpa_vsp_bp;
	pr_info("%s:: VSP BPID %d created config_count %d \n",__FUNCTION__,dpa_vsp_bp->bpid, dpa_vsp_bp->config_count);
	return dpa_vsp_bp;
out:
	return NULL;
}

int dpa_remove_virt_storage_profile(struct eth_iface_info *eth_info)
{
	if(eth_info->vsp_h)
	{
		FM_VSP_Free(eth_info->vsp_h);
		eth_info->vsp_h = NULL;
		_dpa_bp_free(gs_dpa_vsp_bp);
	}
	return 0;
}

int dpa_add_virt_storage_profile(struct net_device *net_dev,
			        struct eth_iface_info *eth_info)
{

	t_FmVspParams           fmVspParams;
	t_LnxWrpFmDev           *p_LnxWrpFmDev;
	t_LnxWrpFmPortDev *port = NULL;
	struct dpa_priv_s	*priv;

	int			 _errno;

	priv = netdev_priv(net_dev);
	port = (t_LnxWrpFmPortDev *)priv->mac_dev->port_dev[RX];
	if(!port->h_DfltVsp)
	{
		_errno = -EINVAL;
		goto out;
	}	

	memset(&fmVspParams, 0, sizeof(fmVspParams));
	p_LnxWrpFmDev = ((t_LnxWrpFmDev *)port->h_LnxWrpFmDev);
	fmVspParams.h_Fm = p_LnxWrpFmDev->h_Dev;
	fmVspParams.portParams.portType = port->settings.param.portType;
	fmVspParams.portParams.portId   = port->settings.param.portId;
	fmVspParams.relativeProfileId   = 1;
	fmVspParams.extBufPools.numOfPoolsUsed = 1;

	if(!gs_dpa_vsp_bp)
	{
		if(!dpa_vsp_bp_probe(net_dev))
		{
			_errno = -ENOMEM;
			goto out;
		}
	}

	fmVspParams.extBufPools.extBufPool[0].id = gs_dpa_vsp_bp->bpid; 
	fmVspParams.extBufPools.extBufPool[0].size = DPAA_VSP_BUF_SIZE;


	eth_info->vsp_h = FM_VSP_Config(&fmVspParams);
	if (!eth_info->vsp_h) {
		_errno = -EINVAL;
		netdev_err(net_dev, "FM_VSP_Config failed %d\n",
				_errno);
		goto out;
	}

	_errno = FM_VSP_ConfigBufferPrefixContent(eth_info->vsp_h, &port->buffPrefixContent);
	if (_errno) {
		_errno = -EINVAL;
		netdev_err(net_dev, "FM_VSP_ConfigBufferPrefixContent failed %d\n",
				_errno);
		goto out;
	}

	_errno = FM_VSP_Init(eth_info->vsp_h);
	if (_errno) {
		_errno = -EINVAL;
		netdev_err(net_dev, "FM_VSP_Init failed %d\n", _errno);
		goto out;
	}
	pr_info("%s:Configured storage profile -relative id %u bpid %u size %u for %s\n",
			__FUNCTION__,
			1,
			fmVspParams.extBufPools.extBufPool[0].id ,
			fmVspParams.extBufPools.extBufPool[0].size,
			net_dev->name);
	return 0;

out:
	dpa_remove_virt_storage_profile(eth_info);
	return _errno;
}

