
/*
 * Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include "dpaa_eth_common.h"
/*#include "dpaa_eth.h"*/
#include "cdx.h"
#include "misc.h"
#include "dpa_wifi.h"
#include "procfs.h"

//#define DEVMAN_DEBUG

static enum qman_cb_dqrr_result voip_traffic_rx_handle(struct qman_portal *portal, 
		struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	const struct qm_fd *fd;
	uint32_t uiLen;
	static int i = 0;

	uiLen = dq->fd.length20;

	fd = &dq->fd;
#ifdef DEVMAN_DEBUG
	if(uiLen)
	{	
		ucPtr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr));
		printk("Dispalying parse result(128 bytes): ucPtr %p, i %d\n", ucPtr, i++);
		display_buff_data(ucPtr, 0x70);
		ucPtr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);
		printk("Displaying the packet(Len %u): ucPtr %p i %d\n", uiLen, ucPtr, i++);
		display_buff_data(ucPtr, uiLen);
		printk("%s()::%d after display packet:\n", __func__, __LINE__);
	}	
#endif
	if (dq->fd.bpid) {
		if (fd->format != qm_fd_sg) {
			struct net_device		*net_dev;
			struct dpa_priv_s		*priv;
			struct dpa_percpu_priv_s	*percpu_priv;
			int                             *count_ptr;
			struct dpa_bp			*dpa_bp;

			if (!fq)
			{
				DPA_ERROR("%s()::%d fq is NULL:\n", __func__, __LINE__);
				return qman_cb_dqrr_consume;
			}

			net_dev = ((struct dpa_fq *)fq)->net_dev;
			priv = netdev_priv(net_dev);
			if (!priv)
			{
				DPA_ERROR("%s()::%d priv is NULL:\n", __func__, __LINE__);
				return qman_cb_dqrr_consume;
			}

			dpa_bp = priv->dpa_bp;
			if (!dpa_bp)
			{
				DPA_ERROR("%s()::%d dpa_bp is NULL:\n", __func__, __LINE__);
				return qman_cb_dqrr_consume;
			}


			/* Trace the Rx fd */
			trace_dpa_rx_fd(net_dev, fq, &dq->fd);

			/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
			percpu_priv = raw_cpu_ptr(priv->percpu_priv);
			count_ptr = raw_cpu_ptr(dpa_bp->percpu_count);

#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
			if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
				return qman_cb_dqrr_stop;
#endif

			/* Vale of plenty: make sure we didn't run out of buffers */

			if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
						CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD )))
				/* Unable to refill the buffer pool due to insufficient
				 * system memory. Just release the frame back into the pool,
				 * otherwise we'll soon end up with an empty buffer pool.
				 */
				dpa_fd_release(net_dev, &dq->fd);
			else
			{
				_dpa_rx(net_dev, portal, priv, percpu_priv, &dq->fd, fq->fqid,
						count_ptr);
			}
		} else {
			DPA_ERROR(KERN_CRIT "%s::cannot handle sg buffers now i %d\n", __FUNCTION__, i++);
		}
	}
	return qman_cb_dqrr_consume;
}

int dpa_get_rtp_qos_slowpath_fq(struct eth_iface_info *eth_info, 
		uint16_t usHash, uint32_t *puiFqId)
{
	*puiFqId = eth_info->voip_fqs[usHash%eth_info->ucNumFqs].fqid;

	return 0;
}

/*struct qman_fq *voip_fqs;*/
/*
 * This function creates the voip frame queue with work queue id 0(high prioriry)
 * for voip traffic receive and avoid delay or drop of voip traffic.
 */
int create_voip_fqs(struct dpa_iface_info *iface_info, uint8_t ucChannelType,
		uint32_t uiCpuMask, uint16_t usNoFqs/*, uint16_t *usCreatedFqs*/)
{
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	const cpumask_t *affine_cpus;
	int32_t	iRxChannelId = 0;
	uint32_t uiPortalChannel[NR_CPUS] = {0};
	int32_t iIndex;
	uint32_t max_cpu;

	iface_info->eth_info.ucNumFqs = 0;
	if ((ucChannelType != DEDICATED_CHANNEL) && (ucChannelType != POOL_CHANNEL))
	{
		DPA_ERROR("%s::%d Invalid Channel type(0x%x).\n", __FUNCTION__, __LINE__, ucChannelType);
		return -1;
	}
	if (ucChannelType == POOL_CHANNEL)
	{
		if (usNoFqs == 0)
		{
			DPA_ERROR("%s::%d Invalid no. of frame queues for pool channel(0x%x).\n", 
					__FUNCTION__, __LINE__, usNoFqs);
			return -1;
		}
		if ((iRxChannelId = dpa_get_channel()) < 0)
		{
			DPA_ERROR("%s::%d Failed to get the RX channel id.\n", 
					__FUNCTION__, __LINE__);
			return -1;
		}
#ifdef DEVMAN_DEBUG
		DPA_ERROR("%s::%d Pool channels RX channel ID %d.\n", 
				__FUNCTION__, __LINE__, iRxChannelId);
#endif
	}
	else
	{
		/* In dedicated channel type it can create fqs equal to no. of cores based on cpumask.*/
		usNoFqs = 0;
		affine_cpus = qman_affine_cpus();
		max_cpu = find_last_bit(cpumask_bits(affine_cpus),NR_CPUS);

		for (iIndex = max_cpu; iIndex >= 0; iIndex--) {
			if (cpu_online(iIndex)) {
				uiPortalChannel[usNoFqs] = qman_affine_channel(iIndex);
				usNoFqs++;
				break; /* One FQ is enough, coming out from loop. */
			}
		}
		if (!usNoFqs) {
			DPA_ERROR("%s::%d unable to get affined portal info\n",
					__FUNCTION__, __LINE__);
			return -1;
		}
#ifdef DEVMAN_DEBUG
		DPA_ERROR("%s::%d Dedicated channels RX channel ID :", __FUNCTION__, __LINE__);
		for (iIndex = 0; iIndex < usNoFqs; iIndex++)
			DPA_ERROR("%d ", uiPortalChannel[iIndex]);
		DPA_ERROR("\n");
#endif
	}


	/* Create  memory for frame queues.*/
	iface_info->eth_info.voip_fqs = kzalloc(sizeof(struct dpa_fq)*usNoFqs, 0);
	if (!iface_info->eth_info.voip_fqs) {
		DPA_ERROR("%s::err allocating dpa_fq mem\n", __FUNCTION__) ;
		return -1;
	}
	dpa_fq = &iface_info->eth_info.voip_fqs[0];
	for (iIndex = 0; iIndex < usNoFqs; iIndex++) {
		/* set FQ parameters */
		fq = &dpa_fq->fq_base;
		/* FQ for voip traffic */
		fq->cb.dqrr = voip_traffic_rx_handle;
		if (qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID, fq)) {
			DPA_ERROR("%s::%d unable to create fq.\n", __FUNCTION__, __LINE__);
			goto err_ret;
		}
		dpa_fq->net_dev = iface_info->eth_info.net_dev;
		dpa_fq->wq = DEFA_WQ_ID;
		dpa_fq->fqid = fq->fqid;

		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		opts.fqid = fq->fqid;
		opts.count = 1;
		opts.we_mask = (QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_DESTWQ |
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
		opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
		if (ucChannelType == POOL_CHANNEL)
			opts.fqd.dest.channel = dpa_fq->channel =iRxChannelId;
		else
			opts.fqd.dest.channel = dpa_fq->channel = uiPortalChannel[iIndex];
		opts.fqd.dest.wq = DEFA_WQ_ID;

		opts.fqd.context_a.stashing.exclusive =
			(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
		opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
		opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
		if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
			DPA_ERROR("%s::%d qman_init_fq failed for fqid %d\n",
					__FUNCTION__, __LINE__, fq->fqid);
			/* TODO: In case of failure, qman_destroy_fq need to be called for all the fqs
			for which initilization is done previously. And also iface_info->eth_info.voip_fqs
			need to freed.
			*/
			qman_destroy_fq(fq, 0);
			goto err_ret;
		}
		/* creating /proc/fqid_stats dir for listing fqids */
		cdx_create_type_fqid_info_in_procfs(fq, UNSPECIFIED, NULL, NULL);
#ifdef DEVMAN_DEBUG
		DPA_ERROR("%s::%d created fq 0x%x chnl id 0x%x\n", 
				__FUNCTION__, __LINE__, fq->fqid, opts.fqd.dest.channel);
#endif
		iface_info->eth_info.ucNumFqs++;
		dpa_fq++;
	}
	iface_info->eth_info.ucNumFqs = usNoFqs;
	return 0;

err_ret:
	for (; iIndex >0; iIndex--) {
		dpa_fq--;
		/* set FQ parameters */
		fq = &dpa_fq->fq_base;

		if (qman_retire_fq(fq, NULL)) {
			DPA_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			return FAILURE;
		}
		if (qman_oos_fq(fq)) {
			DPA_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			return FAILURE;
		}
		cdx_remove_fqid_info_in_procfs(fq->fqid);
		qman_destroy_fq(fq, 0);
#ifdef DEVMAN_DEBUG
		DPA_INFO("%s::destroyed fq 0x%x chnl id 0x%x\n", 
				__FUNCTION__, fq->fqid, eth_info->tx_channel_id);
#endif
	}
	kfree(iface_info->eth_info.voip_fqs);
	return FAILURE;
}


int dpa_create_eth_if_voip_fqs(struct dpa_iface_info *iface_info)
{
	int32_t iRetVal = 0;


#ifdef VOIP_FQ_DEDICATED_CHANNEL
	if ((iRetVal = create_voip_fqs(iface_info, DEDICATED_CHANNEL, CPU_MASK, 0))) {
		DPA_ERROR("%s()::%d Failed to create voip frame queues, error(%d)\n", 
				__func__, __LINE__, iRetVal);
		return iRetVal;
	}
#else
	if ((iRetVal = create_voip_fqs(iface_info, POOL_CHANNEL, 0, VOIP_FRAME_QUEUES))) {
		DPA_ERROR("%s()::%d Failed to create voip frame queues, error(%d)\n", 
				__func__, __LINE__, iRetVal);
		return iRetVal;
	}
#endif
	return 0;
}

#if 0
NOTE: This function can call from deinit context, to free interface voip fqs.
int dpa_destroy_eth_if_voip_fqs(struct dpa_iface_info *iface_info)
{
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	uint8_t ucNumFqs;


	ucNumFqs = iface_info->eth_info.ucNumFqs;
	for (iIndex = 0; iIndex < usNoFqs; iIndex++) {
		/* set FQ parameters */
		fq = &dpa_fq->fq_base;

		if (qman_retire_fq(fq, NULL)) {
			DPA_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			return FAILURE;
		}
		if (qman_oos_fq(fq)) {
			DPA_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			return FAILURE;
		}
		cdx_remove_fqid_info_in_procfs(fq->fqid);
		qman_destroy_fq(fq, 0);
		printk("%s::desroyed fq 0x%x chnl id 0x%x\n", 
				__FUNCTION__, fq->fqid, eth_info->tx_channel_id);
#ifdef DEVMAN_DEBUG
		DPA_INFO("%s::destroyed fq 0x%x chnl id 0x%x\n", 
				__FUNCTION__, fq->fqid, eth_info->tx_channel_id);
#endif
		dpa_fq++;
	}

	return 0;
}
#endif
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
