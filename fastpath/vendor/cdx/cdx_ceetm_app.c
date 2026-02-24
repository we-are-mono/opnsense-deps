/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include <dpaa_eth.h>
#include <dpaa_eth_common.h>
#include <mac.h>
#include "cdx.h"
#include "control_ipv4.h"
#include "lnxwrp_fm.h"
#include "portdefs.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "cdx_common.h"

static struct ceetm_chnl_info qm_chnl_info[CDX_CEETM_MAX_CHANNELS];


static struct qman_fq *ceetm_get_egressfq(void *ctx, uint32_t channel, uint32_t classque, uint32_t ff)
{
	struct ceetm_chnl_info *chnl_ctx;
	struct tQM_context_ctl *qm_ctx;
	struct qman_fq *fq;
	uint32_t pp_no;

	if (channel > CDX_CEETM_MAX_CHANNELS)
		return NULL;
	if (classque >= CDX_CEETM_MAX_QUEUES_PER_CHANNEL)
		return NULL;
	if (!channel) {
		qm_ctx = (struct tQM_context_ctl *)ctx;
		if (!qm_ctx) {
			ceetm_err("%s::invalid channel context\n", __FUNCTION__);
			return NULL;
		}
		/* get least prio channel on this interface */
		channel = (CDX_CEETM_MAX_CHANNELS - 1);
		while (1) {
			if (qm_ctx->chnl_map & (1 << channel)) 
				break;
			channel--;
		}
		ceetm_dbg("%s::incoming channel reassigned as %d\n", __FUNCTION__, channel);
	} else
		channel--;
	chnl_ctx = &qm_chnl_info[channel];
	fq =  &chnl_ctx->cq_info[classque].ceetmfq.egress_fq;
	if(chnl_ctx->cq_info[classque].cq_shaper_enable && ff) {
		pp_no = ((chnl_ctx->cq_info[classque].pp_num) << 24);
		fq->fqid = (pp_no|fq->fqid);
	}
	else if(chnl_ctx->cq_info[classque].cq_shaper_enable == DISABLE_POLICER)
		fq->fqid = (fq->fqid & 0x00FFFFFF); /* ensure MSByte is set to Zero */

	/*ceetm_dbg("%s::markval %08x egress fq %p fqid %d(%x)\n", __FUNCTION__, markval, fq, fq->fqid, fq->fqid);*/
	return (fq);
}

struct qman_fq *cdx_get_txfq(struct eth_iface_info *eth_info, void *info)
{
	union ctentry_qosmark *qosmark = (union ctentry_qosmark *)info;
	uint32_t quenum,ff = 1;

#ifdef ENABLE_EGRESS_QOS
	struct dpa_priv_s *priv;
	struct qman_fq *egress_fq;

	priv = netdev_priv(eth_info->net_dev);
	if (priv->ceetm_en) {
		egress_fq = ceetm_get_egressfq(priv->qm_ctx, qosmark->chnl_id, qosmark->queue,ff);
		if (!egress_fq) {
			ceetm_err("%s::unable to get ceetm fqid for markval %x\n",
				__FUNCTION__, qosmark->markval);
			return NULL;
		}
		return (egress_fq);
	} 
#endif
	/* QOS not enabled on this interface */
	quenum = (qosmark->queue & (DPAA_FWD_TX_QUEUES - 1));
	return (&eth_info->fwd_tx_fqinfo[quenum]);
}

int cdx_get_tx_dscp_fq_map(struct eth_iface_info *eth_info, uint8_t *is_dscp_fq_map, void* info)
{
#ifdef ENABLE_EGRESS_QOS
	struct dpa_priv_s *priv;
	U32 mark = 0; /* Default queue */
	union ctentry_qosmark *qosmark = (union ctentry_qosmark *)&mark;

	if (is_dscp_fq_map)
	{
		if(info)
			qosmark = info;

		priv = netdev_priv(eth_info->net_dev);
		if ((priv) && (priv->ceetm_en)) {
			if ((!qosmark->markval) && /* No QOSCONNMARK */
				((struct tQM_context_ctl *)priv->qm_ctx)->dscp_fq_map) /* DSCP FQ MAP enabled */
				*is_dscp_fq_map = 1;
			else
				*is_dscp_fq_map = 0;
		}
	} 
#endif
	return 0;
}

/*
 * This function returns the dscp fq pointer from corresponding interface QM CTX. *
 * In success case it returns the fq pointer otherwise returns NULL.              *
*/
static struct qman_fq *ceetm_get_dscp_fq(void *ctx, uint8_t dscp)
{
	struct tQM_context_ctl *qm_ctx = (struct tQM_context_ctl *)ctx;
	
	if (!qm_ctx->dscp_fq_map)
		return NULL;
	if (dscp >= MAX_DSCP)
	{
		ceetm_err("Invalid dscp value %d ox tx iface <%s>\n", dscp, qm_ctx->iface_info->name);
		return NULL;
	}

	return qm_ctx->dscp_fq_map->dscp_fq[dscp];
}

/* get count of frames on a CEETM class queue */
static int ceetm_get_fqcount(struct ceetm_chnl_info *chnl_ctx, uint32_t classque, uint32_t *fqcount)
{
	struct qm_mcr_ceetm_cq_query *query;
	struct qm_ceetm_cq *cq;
	struct tQM_context_ctl *qm_ctx;

	qm_ctx = chnl_ctx->qm_ctx;
	if (!qm_ctx) {
		ceetm_err("%s::invalid channel context\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	query = kzalloc(sizeof(struct qm_mcr_ceetm_cq_query), GFP_KERNEL);
	if (!query) {
		ceetm_err("%s::error allocating query\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	cq = (struct qm_ceetm_cq *)chnl_ctx->cq_info[classque].cq;
	qm_ctx = chnl_ctx->qm_ctx;
	if (qman_ceetm_query_cq(cq->idx, qm_ctx->port_info->fm_index, query)) {
		ceetm_err("%s::error getting ceetm cq fields\n", __FUNCTION__);
		kfree(query);
		return CEETM_FAILURE;
	}
	*fqcount = query->frm_cnt;
	kfree(query);
	return CEETM_SUCCESS;
}

/* program lni shaper */
static int ceetm_program_port_shaper(struct tQM_context_ctl *qm_ctx, struct qm_ceetm_rate *rate,
				struct qm_ceetm_rate *limit, uint32_t bsize)
{
	struct qm_ceetm_lni *lni;

	/* program lni shaper */	
	ceetm_dbg("%s::port rate whole %x, fraction %x, limit whole %x, fraction %x, bsize %d\n",
		__FUNCTION__, rate->whole, rate->fraction, 
		limit->whole, limit->fraction, bsize);
	lni = qm_ctx->lni;
	if (qman_ceetm_lni_set_commit_rate(lni, rate, bsize)) {
		ceetm_err("%s %d. qman_ceetm_lni_set_commit_rate failed \n", __FUNCTION__, __LINE__);
		return CEETM_FAILURE;
	}
	if (qman_ceetm_lni_set_excess_rate(lni, limit, bsize)) {  
		ceetm_err("%s %d. qman_ceetm_lni_set_commit_rate failed \n", __FUNCTION__, __LINE__);
		return CEETM_FAILURE;
	}
	ceetm_dbg("%s::port shaper programmed\n", __FUNCTION__); 
	return CEETM_SUCCESS;
}

static int ceetm_program_channel_shaper(struct ceetm_chnl_info *chnl_ctx, struct qm_ceetm_rate *rate,
				struct qm_ceetm_rate *limit, uint32_t bsize)
{
	struct qm_ceetm_channel *channel;

	/* program channel shaper */	
	ceetm_dbg("%s::channel rate whole %x, fraction %x, limit whole %x, fraction %x, bsize %d\n",
		__FUNCTION__, rate->whole, rate->fraction, 
		limit->whole, limit->fraction, bsize);
	channel = chnl_ctx->channel;
	if (qman_ceetm_channel_set_commit_rate(channel, rate, bsize)) {
		ceetm_err("%s %d. qman_ceetm_lni_set_commit_rate failed \n", __FUNCTION__, __LINE__);
		return CEETM_FAILURE;
	}
	if (qman_ceetm_channel_set_excess_rate(channel, limit, bsize)) {  
		ceetm_err("%s %d. qman_ceetm_lni_set_commit_rate failed \n", __FUNCTION__, __LINE__);
		return CEETM_FAILURE;
	}
	ceetm_dbg("%s::channel shaper programmed\n", __FUNCTION__); 
	return CEETM_SUCCESS;
}

/* alloc lni and isp for the interface */
int ceetm_create_lni(struct tQM_context_ctl *qm_ctx)
{
	int index;
	struct qm_ceetm_lni *lni;
	struct qm_ceetm_sp *sp;

	/* use idx as lower part of tx_channel_id */
	index = (qm_ctx->iface_info->eth_info.tx_channel_id & 0xf);
	ceetm_dbg("%s::lni index %d\n", __FUNCTION__, index);
	/* claim a sub portal */
	sp = NULL;
	lni = NULL;
	ceetm_dbg("%s::claiming sp\n", __FUNCTION__);
	if(qman_ceetm_sp_claim(&sp, qm_ctx->port_info->fm_index, index)) {
    		ceetm_err("%s::unable to claim sp_index %d\n", __FUNCTION__, index);
		goto err_ret;
	}
	/* claim a LNI */
	ceetm_dbg("%s::claiming lni\n", __FUNCTION__);
	if(qman_ceetm_lni_claim(&lni, qm_ctx->port_info->fm_index, index)) {
		ceetm_err("%s %d. qman_ceetm_lni_claim failed \n", __FUNCTION__, __LINE__);
		goto err_ret;
	}
	qm_ctx->lni = lni;
	qm_ctx->sp = sp;
	ceetm_dbg("%s::allocated lni %p for index %d\n", __FUNCTION__, lni, lni->idx);
	return CEETM_SUCCESS;
err_ret:
	if(lni)
		qman_ceetm_lni_release(lni);
	if(sp)
		qman_ceetm_sp_release(sp);
	return CEETM_FAILURE;
}

/* set up lni, disable shaping by default */
static int ceetm_setup_lni(struct tQM_context_ctl *qm_ctx)
{
	struct shaper_info *shinfo;
	struct qm_ceetm_rate token_er;

	ceetm_dbg("%s::setting lni,sp\n", __FUNCTION__);
	if(qman_ceetm_sp_set_lni(qm_ctx->sp, qm_ctx->lni)) {
		ceetm_err("%s %d. qman_ceetm_sp_set_lni failed \n", __FUNCTION__, __LINE__);
		return CEETM_FAILURE;
	}
	qm_ctx->lni->sp = qm_ctx->sp;
	/* enable lni shaper coupled */
	if (qman_ceetm_lni_enable_shaper(qm_ctx->lni, 1, CEETM_DEFA_OAL)) {
		ceetm_err("%s %d. qman_ceetm_lni_enable_shaper failed \n", __FUNCTION__, __LINE__);
		return CEETM_FAILURE;
	}
	/* disable shaper by setting large values for port shaper*/
	shinfo = &qm_ctx->shaper_info;
	shinfo->enable = 0;
	shinfo->token_cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
	shinfo->token_cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	token_er.whole = 0;
	token_er.fraction = 0;
	shinfo->bsize = CEETM_DEFA_BSIZE;
	if (ceetm_program_port_shaper(qm_ctx, &shinfo->token_cr, &token_er,
			shinfo->bsize)) { 
		ceetm_err("%s::unable to program lni shaper, idx %d\n", __FUNCTION__, qm_ctx->lni->idx);
		return CEETM_FAILURE;
	}	
	ceetm_dbg("%s:setup for lni %p, index %d complete\n", __FUNCTION__, qm_ctx->lni, qm_ctx->lni->idx);
	return CEETM_SUCCESS;
}


/* enable shaping or disable shaping on lni */
static int ceetm_cfg_shaper(void *ctx, uint32_t type, PQosShaperConfigCommand params)
{
	struct qm_ceetm_rate token_cr;
	struct qm_ceetm_rate token_er;
	struct shaper_info *shinfo;
	struct tQM_context_ctl *qm_ctx;
	struct ceetm_chnl_info *chnl_ctx;
	uint32_t cfg;
	uint32_t enable;

	cfg = 0;
	if (type == PORT_SHAPER_TYPE) {
		qm_ctx = (struct tQM_context_ctl *)ctx;
		shinfo = &qm_ctx->shaper_info;
		token_er.whole = 0;
		token_er.fraction = 0;
	} else {
		chnl_ctx = (struct ceetm_chnl_info *)ctx;
		shinfo = &chnl_ctx->shaper_info;
		token_er.whole = CEETM_TOKEN_WHOLE_MAXVAL;
		token_er.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	}
	
	if (params->cfg_flags & SHAPER_CFG_VALID) {
		/* new configuration available */
		if(qman_ceetm_bps2tokenrate((params->rate * 1000), &token_cr, 0)) {
			ceetm_err("%s:CR qman_ceetm_bps2tokenrate failed\n", __FUNCTION__);
			return CEETM_FAILURE;
		}
		ceetm_dbg("%s::CR Rate %d whole %d fraction %d\n", __FUNCTION__, 
			params->rate, token_cr.whole, token_cr.fraction);

		shinfo->rate = (params->rate * 1000);
		shinfo->bsize = params->bsize;
		shinfo->token_cr = token_cr;
		/* if shaper enabled by default write configuration */
		if (shinfo->enable)
			cfg = 1;
	} 
	enable = shinfo->enable;
	if (params->enable == SHAPER_ON) {
		/* load configured rate */
		token_cr = shinfo->token_cr;
		/* configure hardware */
		cfg = 1;
		enable = 1;
	} else {
		if (params->enable == SHAPER_OFF) {
			/* set limits very high to disable shaper */
			token_cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
			token_cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
			/* configure hardware with disable values*/
			cfg = 1;
			enable = 0;
		}
	}
	if (cfg) {
		if (type == PORT_SHAPER_TYPE) {
			/* Port shaper configuration */
			if (ceetm_program_port_shaper(qm_ctx, &token_cr, &token_er, 
				shinfo->bsize)) {
				return CEETM_FAILURE;
			}
		} else {
			/* channel shaper configuration */
			if (ceetm_program_channel_shaper(chnl_ctx, &token_cr, &token_er,
				shinfo->bsize)) {
				return CEETM_FAILURE;
			}
		}
	}
	shinfo->enable = enable;
	ceetm_dbg("%s::CR and ER configured, enable %d\n", __FUNCTION__, enable);
	return CEETM_SUCCESS;
}

/* release lni */
int ceetm_release_lni(void *handle)
{
	struct qm_ceetm_lni *lni;
	uint32_t lni_index;

	if (!handle)
		return CEETM_FAILURE;
	lni = (struct qm_ceetm_lni *)handle;
	lni_index = lni->idx;
	ceetm_dbg("%s::releasing lni %p index %d\n", __FUNCTION__, lni, lni_index);
	if (!qman_ceetm_lni_release(lni)) {
		if (qman_ceetm_sp_release(lni->sp)) {
			ceetm_err("%s:sp release failed on lni %p(%d)\n", 
				__FUNCTION__, lni, lni->idx);
			return CEETM_FAILURE;
		}
	} else {
		ceetm_err("%s:lni %p(%d) release failed\n", __FUNCTION__, handle, lni_index);
		return CEETM_FAILURE;
	}
	return CEETM_SUCCESS;
}

static int ceetm_create_ccg_for_class_queue(struct ceetm_chnl_info *chnl_ctx, uint32_t classque)
{
	struct qm_ceetm_channel *channel;
	struct qm_ceetm_ccg *ccg;

	channel = (struct qm_ceetm_channel *)chnl_ctx->channel;
#ifdef CEETM_USE_CONG_STATE_CHANGE_NOTIFICATION 
	ceetm_dbg("%s::congestion state change notification enabled\n", __FUNCTION__);
	if (qman_ceetm_ccg_claim(&ccg, channel, chnl_ctx->cq_info[classque].ceetm_idx, 
			ceetm_cscn_handler, NULL)) {
		ceetm_err("%s::qman_ceetm_ccg_claim failed for channel %p\n", __FUNCTION__,
			channel);
		return CEETM_FAILURE;
	}
#else
	ceetm_dbg("%s::congestion state change notification disabled\n", __FUNCTION__);
	if (qman_ceetm_ccg_claim(&ccg, channel, chnl_ctx->cq_info[classque].ceetm_idx, NULL, NULL)) {
		ceetm_err("%s::qman_ceetm_ccg_claim failed for channel %p\n", __FUNCTION__,
			channel);
		return CEETM_FAILURE;
	}
#endif
	ceetm_dbg("%s::CCG claimed ccg %p for class queue %d\n", __FUNCTION__, ccg, classque);
	chnl_ctx->cq_info[classque].ccg = ccg;
	return CEETM_SUCCESS;
}

static void ceetm_num_to_2powN_multiple(uint32_t num_in, uint32_t *num, uint32_t *mul, 
                               uint32_t maxbits, uint32_t maxbits_mul)
{
	int ii;
	int msbbit;

	msbbit = 0;
	for(ii = 0; ii < (sizeof(ii) * 8); ii++) {
		if(num_in & (1 << ii))
			msbbit = ii;
	}

	if(msbbit < maxbits_mul) {
		*num = 0;
		*mul = num_in;
	} else { 
		if(msbbit < (maxbits_mul + (1 << maxbits) - 1)) {
			*num = msbbit - maxbits_mul + 1;
			*mul = num_in >> (*num);
		} else {
			*num = maxbits;
			*mul = (1 << maxbits_mul) - 1;
		}
	}
}

static int ceetm_cfg_td_on_class_queue(struct ceetm_chnl_info *chnl_ctx, uint32_t index, uint32_t tdthresh)
{
	struct qm_ceetm_ccg *ccg;
	struct qm_ceetm_ccg_params params;
	uint16_t mask;
	unsigned int uiNum, uiMul;

	memset(&params, 0, sizeof(struct qm_ceetm_ccg_params));
	params.mode = 1; /* use framecount not bytes */
	mask =  (QM_CCGR_WE_TD_EN | QM_CCGR_WE_MODE | QM_CCGR_WE_TD_MODE); 
	if (!tdthresh) {
		params.td_en = 0; /* enable taildrop congestion avoidance algo */
		params.td_mode = 1; /* use congestion threshold not state */
		params.cscn_en = 0; /* no congestion state change notification */
		params.td_thres.Tn = 0;
		params.td_thres.TA = 0;
	} else {
		params.td_en = 1; /* enable taildrop congestion avoidance algo */
		params.td_mode = 1; /* use congestion threshold not state */
		ceetm_num_to_2powN_multiple(tdthresh, &uiNum, &uiMul, 5, 8);
		params.td_thres.Tn = uiNum;
		params.td_thres.TA = uiMul;
		mask |= (QM_CCGR_WE_TD_THRES); 
#ifdef CEETM_USE_CONG_STATE_CHANGE_NOTIFICATION
		params.cscn_en = 1; /* enable congestion state change notification */
		params.cs_thres_in.TA = QOS_CEETM_CS_THRSIN_TA;
		params.cs_thres_in.Tn = QOS_CEETM_CS_THRSIN_TN;
		params.cs_thres_out.TA = QOS_CEETM_CS_THRSOUT_TA;
		params.cs_thres_out.Tn = QOS_CEETM_CS_THRSOUT_TN;
		mask |= (QM_CCGR_WE_CSCN_EN | QM_CCGR_WE_CS_THRES_IN | QM_CCGR_WE_CS_THRES_OUT);
#else
		params.cscn_en = 0; /* no congestion state change notification */
#endif
		ceetm_dbg("%s::setting congestion algo as QOS_CEETM_TAIL_DROP\n", __FUNCTION__);
	}
	ccg = (struct qm_ceetm_ccg *)chnl_ctx->cq_info[index].ccg;
	if (qman_ceetm_ccg_set(ccg, mask, &params)) {
		ceetm_err("%s::unable to set ccg parameters\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	chnl_ctx->cq_info[index].qdepth = tdthresh;
	return CEETM_SUCCESS;
}

/* enqueue rejection notification handler */
static void egress_ern_handler(struct qman_portal *portal, struct qman_fq *fq, const struct qm_mr_entry *msg)
{
	const struct qm_fd *fd;
	struct ceetm_fq *pceetm_fq;
	struct sk_buff *skb;
	const struct dpa_priv_s *priv;
	uint32_t offset;

	fd = &(msg->ern.fd);
	offset = offsetof(struct ceetm_fq, egress_fq);
	pceetm_fq = (struct ceetm_fq *)((char *)fq - offset); 
	/* use BPID here */
	ceetm_dbg("%s::fqid %d(%x), bpid %d, rc %d\n", __FUNCTION__,
			fq->fqid, fq->fqid, fd->bpid, msg->ern.rc); 
	if (fd->bpid != 0xff) {
		dpa_fd_release(pceetm_fq->net_dev, fd);
	} else {
		/* release SKB */
		priv = netdev_priv(pceetm_fq->net_dev);
		skb = _dpa_cleanup_tx_fd(priv, fd);
		dev_kfree_skb_any(skb); 
	}
}

/* configure any of the prio or wbfq class queue of a channel */
/* queues 0-7 are strict prio and queues 8-15 are in single WBFQ group */
int ceetm_create_cq(struct ceetm_chnl_info *chnl_ctx, uint32_t classque) 
{
	struct qm_ceetm_channel *channel;
	struct qm_ceetm_ccg *ccg;
	struct qm_ceetm_cq *cq;
	struct qm_ceetm_lfq *lfq;
	uint64_t context_a;
	struct classque_info *cqinfo;
	uint32_t type;
	uint32_t ceetm_quenum;

	if (classque < CEETM_WBFS_START)
		type = CEETM_PRIO_QUEUE; 
	else {
		if (classque >= CDX_CEETM_MAX_QUEUES_PER_CHANNEL) {
			ceetm_err("%s::invalid value %d for channel index\n", 
				__FUNCTION__, classque);
			return CEETM_FAILURE;
		}
		type = CEETM_WBFQ_QUEUE; 
	}
	ceetm_quenum = chnl_ctx->cq_info[classque].ceetm_idx;
	ceetm_dbg("%s::channel %p chnl_idx %d, cq %d, ceetm_cq %d\n", __FUNCTION__,
			chnl_ctx, chnl_ctx->idx, classque, ceetm_quenum);
	channel = (struct qm_ceetm_channel *)chnl_ctx->channel;
	cqinfo = &chnl_ctx->cq_info[classque];
	ccg = (struct qm_ceetm_ccg *)cqinfo->ccg;
	if (!ccg) {
		ceetm_err("%s::No CCG for Class Queue %d, chnl %p(%d)\n", 
			__FUNCTION__, classque, channel, channel->idx);
		return CEETM_FAILURE;
	}
	if (type == CEETM_PRIO_QUEUE) {
		/* claim a prio class queue */
		ceetm_dbg("%s::claiming class que\n", __FUNCTION__);
		if (qman_ceetm_cq_claim(&cq, channel, ceetm_quenum, ccg)) {
			ceetm_err("%s::Failed to claim Class Queue %d for chnl %p(%d)\n", 
				__FUNCTION__, classque, channel, channel->idx);
			return CEETM_FAILURE;
		}
		cqinfo->ch_shaper_enable = 0;
		ceetm_dbg("%s::setting CR eligibility\n", __FUNCTION__);
		/* no CR eligibility */
		if (qman_ceetm_channel_set_cq_cr_eligibility(channel, ceetm_quenum, 0)) {
			ceetm_err("%s::Failed to set cr eligibility of cq %d chnl %p(%d)\n", __FUNCTION__,
				classque, channel,  channel->idx);			
			goto err_ret;
		}
		ceetm_dbg("%s::setting ER eligibility\n", __FUNCTION__);
		/* Set ER eligibility, disabling shaping */
		if (qman_ceetm_channel_set_cq_er_eligibility(channel, ceetm_quenum, 1)) {
			ceetm_err("%s::Failed to set er eligibility of cq %d chnl %p(%d)\n", __FUNCTION__,
				classque, channel,  channel->idx);			
			goto err_ret;
		}
	} else {
  		struct qm_ceetm_weight_code weight_code;

		/* all wbfq cq are in a single group, GRP A */
		ceetm_dbg("%s::Claiming group A\n", __FUNCTION__);
		if (qman_ceetm_cq_claim_A(&cq, channel, ceetm_quenum, ccg)) {
			ceetm_err("%s::Failed to claim Class Queue A for CH %d\n", 
				__FUNCTION__, channel->idx);
			return CEETM_FAILURE;
		}
		/* set shaper eligiblity */
		if (qman_ceetm_channel_set_group_cr_eligibility(channel, 0, 0)) {
			ceetm_err("%s::Failed to set group cr eligibility of cq %d chnl %p(%d)\n", __FUNCTION__,
				classque, channel,  channel->idx);			
			return CEETM_FAILURE;
		}
		if (qman_ceetm_channel_set_group_er_eligibility(channel, 0, 1)) {
			ceetm_err("%s::Failed to set group er eligibility of cq %d chnl %p(%d)\n", __FUNCTION__,
				classque, channel,  channel->idx);			
			return CEETM_FAILURE;
		}

		/* Set the Queue Weight */
		cqinfo->weight = DEFAULT_WBFQ_WEIGHT;	
		if (qman_ceetm_ratio2wbfs(DEFAULT_WBFQ_WEIGHT, 1, &weight_code, 0)) {
			ceetm_err("%s::Failed to convert weight %d channel %d\n",
				__FUNCTION__, DEFAULT_WBFQ_WEIGHT, channel->idx);
			return CEETM_FAILURE;
		}
		ceetm_dbg("%s::setting weight\n", __FUNCTION__);
		if (qman_ceetm_set_queue_weight(cq, &weight_code)) {
			ceetm_err("%s::Failed to set weight %d for channel %d\n",
				__FUNCTION__, DEFAULT_WBFQ_WEIGHT, channel->idx);
			return CEETM_FAILURE;
		}
	}
	cqinfo->cq = cq;
	ceetm_dbg("%s::claimed cq %p, channel %p(%d), cqid %d\n", __FUNCTION__, cq, channel,
			channel->idx, classque);
	/* Claim a LFQ */
	ceetm_dbg("%s::claiming lfq\n", __FUNCTION__);
	if (qman_ceetm_lfq_claim(&lfq, cq)) {
		ceetm_err("%s::Failed to claim LFQ for cq %p(%d)\n", __FUNCTION__, 
			cq, cq->idx);
		goto err_ret;
	}
	ceetm_dbg("%s::claimed lfq %p idx %x for cq %p(%d, ceetm_que %d)\n", __FUNCTION__, lfq, lfq->idx, 
			cq, classque, ceetm_quenum);
	cqinfo->lfq = lfq;
	context_a = (uint64_t)VQA_DPAA_VAL_TO_RELEASE_BUFFER;
	ceetm_dbg("%s::set context\n", __FUNCTION__);
	if (qman_ceetm_lfq_set_context(lfq, context_a, 0)) { 
		ceetm_err("%s::set context_a for lfq %p failed\n",__FUNCTION__,
			lfq); 
		goto err_ret;
	}
	/* set Enque Rejection Notification handler */	
	lfq->ern = egress_ern_handler;
	/* create LFQ for egress */
	ceetm_dbg("%s::creating lfq\n", __FUNCTION__);
	if (qman_ceetm_create_fq(lfq, &cqinfo->ceetmfq.egress_fq)) {
		ceetm_err("%s::unable to create lfq %p\n",__FUNCTION__,
			lfq); 
		goto err_ret;
	}
	ceetm_dbg("%s::created fq %p, fqid %x(%d) for lfq %p, classque %d, channel %d\n", 
			__FUNCTION__, &cqinfo->ceetmfq, 
			cqinfo->ceetmfq.egress_fq.fqid, 
			cqinfo->ceetmfq.egress_fq.fqid, 
			lfq, classque, channel->idx);
	return CEETM_SUCCESS;
err_ret:
	if (cqinfo->lfq) {
		if (!qman_ceetm_lfq_release(cqinfo->lfq))
			cqinfo->lfq = NULL;
	}
	if (cqinfo->cq) {
		if (!qman_ceetm_cq_release(cqinfo->cq))
			cqinfo->cq = NULL;
	}
	return CEETM_FAILURE;
}

static void ceetm_cq_policer_fill_defaults(t_FmPcdPlcrProfileParams *Params)
{
	Params->algSelection = e_FM_PCD_PLCR_RFC_2698;
	Params->colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	/*color as red by default*/
	Params->color.dfltColor = e_FM_PCD_PLCR_RED;
	/*override color is RED */
	Params->color.override = e_FM_PCD_PLCR_RED;
	/*set algorithm mode as bytes/sec (kilobits/sec)*/
	Params->nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;

	Params->nonPassthroughAlgParams.committedBurstSize = DEFAULT_CQ_BYTE_MODE_CBS;
	Params->nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_CQ_BYTE_MODE_PBS;
	Params->nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
	Params->nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;

	Params->nextEngineOnGreen = e_FM_PCD_DONE;
	Params->paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
	Params->nextEngineOnYellow = e_FM_PCD_DONE;
	Params->paramsOnYellow.action = e_FM_PCD_DROP_FRAME;
	Params->nextEngineOnRed =e_FM_PCD_DONE;
	Params->paramsOnRed.action = e_FM_PCD_DROP_FRAME;
}

static int ceetm_create_cq_policer_profiles(t_Handle h_FmPcd, struct classque_info *cqinfo, uint32_t profile)
{
	t_FmPcdPlcrProfileParams Params;


	/* init default cir and pir values */
	cqinfo->shaper_rate = DEFAULT_CQ_CIR_VALUE;

	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.id.newParams.profileType = e_FM_PCD_PLCR_SHARED;
	Params.id.newParams.relativeProfileId = profile;

	Params.nonPassthroughAlgParams.committedInfoRate = DEFAULT_CQ_CIR_VALUE;
	Params.nonPassthroughAlgParams.peakOrExcessInfoRate = DEFAULT_CQ_PIR_VALUE;

	ceetm_cq_policer_fill_defaults(&Params);

	cqinfo->pp_handle = FM_PCD_PlcrProfileSet(h_FmPcd, &Params);
	if (!cqinfo->pp_handle) {
		printk("%s::unable to set profile for profile %d\n",
		 __FUNCTION__, profile);
		return CEETM_FAILURE;
	}
	cqinfo->pp_num = FmPcdPlcrProfileGetAbsoluteId(cqinfo->pp_handle);

	ceetm_dbg("%s:plcr profile created for  handle %p,profile_id %d\n",
		__FUNCTION__, cqinfo->pp_handle,cqinfo->pp_num);
	ceetm_dbg("cir %u, pir %u, cbs %d, pbs %d\n",
			Params.nonPassthroughAlgParams.committedInfoRate,
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate,
			Params.nonPassthroughAlgParams.committedBurstSize,
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize);

	cqinfo->cq_shaper_enable = DISABLE_POLICER;
	return CEETM_SUCCESS;
}

int ceetm_configure_cq_policer_profiles(struct classque_info *cq_info,void *pcd_handle,uint32_t enable,uint32_t shaper_rate)
{
	void *handle;
	t_FmPcdPlcrProfileParams Params;


	if (enable == DISABLE_POLICER) {
		cq_info->cq_shaper_enable = enable;
		cq_info->shaper_rate = shaper_rate;
		ceetm_dbg("%s::plcr profile is disabled on cq queue %p\n",__FUNCTION__,cq_info);
		return CEETM_SUCCESS;
	}

	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = cq_info->pp_handle;

	Params.nonPassthroughAlgParams.committedInfoRate = shaper_rate;
	Params.nonPassthroughAlgParams.peakOrExcessInfoRate = shaper_rate;

	ceetm_cq_policer_fill_defaults(&Params);

	handle = FM_PCD_PlcrProfileSet(pcd_handle, &Params);
        if (!handle) {
		ceetm_err("%s::unable to modify profile for cq queue %p\n",
			__FUNCTION__,cq_info);
		return CEETM_FAILURE;
        }
	cq_info->cq_shaper_enable = enable;
	cq_info->shaper_rate = shaper_rate;

	ceetm_dbg("%s::plcr profile modified for cq queue %p, handle %p\n",
	 __FUNCTION__, cq_info, handle);

	return CEETM_SUCCESS;
}

static int ceetm_create_queues(struct ceetm_chnl_info *chnl_ctx) 
{
	uint32_t ii; 
	struct qm_ceetm_channel *channel;

	channel = (struct qm_ceetm_channel *)chnl_ctx->channel;
	/* set WBFQ priority */
	chnl_ctx->wbfq_priority = CEETM_DEFA_WBFQ_PRIORITY;
	ii = GET_CEETM_PRIORITY(CEETM_DEFA_WBFQ_PRIORITY);
	ceetm_dbg("setting wbfq priority\n");
	ceetm_dbg("%s::setting wbfq priority, cfg->prio %d, ceetm_prio %d\n",
		__FUNCTION__, chnl_ctx->wbfq_priority, ii);
	if(qman_ceetm_channel_set_group(channel, 0, ii, ii)) {
		ceetm_err("%s::qman_ceetm_channel_set_group failed\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	/* set ceetm_cq ids in the cq structure */
	for (ii = 0; ii < NUM_CLASS_QUEUES; ii++) {
		chnl_ctx->cq_info[ii].ceetm_idx = GET_CEETM_PRIORITY(ii);
	}
	for (ii = 0; ii < NUM_CLASS_QUEUES; ii++) {
		/* create ccg for class queue */
		ceetm_dbg("......................................................\n");
		if (ceetm_create_ccg_for_class_queue(chnl_ctx, ii)) {
			ceetm_err("%s::ceetm_create_for_class_queue failed %p\n", __FUNCTION__, channel);
			return CEETM_FAILURE;
		}
		/* set TD */
		if (ceetm_cfg_td_on_class_queue(chnl_ctx, ii, DEFAULT_CQ_DEPTH)) {
			ceetm_err("%s::ceetm_cfg_ccg_to_class_queue failed on chnl %p\n", __FUNCTION__, channel);
			return CEETM_FAILURE;
		}
		ceetm_dbg("%s::ccg configured to class que\n", __FUNCTION__); 
		/* create class queues */
		if (ceetm_create_cq(chnl_ctx, ii)) {
			ceetm_err("%s::ceetm_cfg_prio_class_queue failed on chnl %p\n", __FUNCTION__, channel);
			return CEETM_FAILURE;
		}
		ceetm_dbg("%s::ceetm_create_cq done on sp chnl %p\n", __FUNCTION__, channel); 
	}
	return CEETM_SUCCESS;
}

static int ceetm_create_channel(struct ceetm_chnl_info *qm_channel)
{
	struct qm_ceetm_channel *channel;
	struct qm_ceetm_rate er_rate;

	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel) {
		ceetm_err("%s::unable to allocate channel structure\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	if (qman_alloc_ceetm0_channel(&channel->idx)) {
		ceetm_err("%s::unable to allocate channel on ceetm0\n", __FUNCTION__);
		kfree(channel);
		return CEETM_FAILURE;
	}
	INIT_LIST_HEAD(&channel->class_queues);
        INIT_LIST_HEAD(&channel->ccgs);
	qm_channel->channel = channel;
	/* Enable Shaper by default, do not couple CR and ER */
	if (qman_ceetm_channel_enable_shaper(channel, 0)) {
		ceetm_err("%s::unable to enable shaper for chnl %p\n",
			__FUNCTION__, channel);
		return CEETM_FAILURE;
	}
	er_rate.whole = CEETM_TOKEN_WHOLE_MAXVAL;
	er_rate.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	/* set max possible rate as default value */
	if (ceetm_program_channel_shaper(qm_channel, &qm_channel->shaper_info.token_cr, &er_rate,
		qm_channel->shaper_info.bsize)) {
		ceetm_err("%s::unable to configure shaper for chnl %p\n",
			__FUNCTION__, qm_channel);
		return CEETM_FAILURE;
	}
	ceetm_dbg("%s::created channel %d::%p\n", __FUNCTION__, qm_channel->idx, channel);
	if (ceetm_create_queues(qm_channel)) {
		ceetm_err("%s::unable to create queues on channel %p\n", __FUNCTION__, channel);
		return CEETM_FAILURE;
	}
	return CEETM_SUCCESS;
}

int ceetm_init_channels(void)
{
	uint32_t ii;
	uint32_t jj;
	struct ceetm_chnl_info *chinfo;
	struct classque_info *cqinfo;
	struct qm_ceetm_rate cr;
	uint64_t rate;

	memset(&qm_chnl_info, 0, (CDX_CEETM_MAX_CHANNELS * sizeof(struct ceetm_chnl_info)));
	chinfo = &qm_chnl_info[0];
	cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
	cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	if (qman_ceetm_tokenrate2bps(&cr, &rate, 0)) {
		ceetm_err("%s::unable to deduce rate for shaper\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		chinfo->wbfq_priority = CEETM_DEFA_WBFQ_PRIORITY;
		chinfo->wbfq_chshaper = 0;
		chinfo->shaper_info.bsize = CEETM_DEFA_BSIZE;
		chinfo->shaper_info.token_cr = cr; 
		chinfo->shaper_info.rate = rate;
		chinfo->shaper_info.enable = 0;
		chinfo->idx = ii;
		cqinfo = &chinfo->cq_info[0];
		for (jj = 0; jj < MAX_SCHEDULER_QUEUES; jj++) { 
			if (jj >= NUM_PQS)
				cqinfo->weight = DEFAULT_WBFQ_WEIGHT;
			else
				cqinfo->ch_shaper_enable = 0;
			cqinfo->qdepth = DEFAULT_CQ_DEPTH;
			cqinfo++;
		}
		if (ceetm_create_channel(chinfo))
			return CEETM_FAILURE;
		chinfo++;
	}
	/* register functions to return CEETM egress FQID */
	if (dpa_register_ceetm_get_egress_fq(ceetm_get_egressfq, ceetm_get_dscp_fq)) {
		ceetm_err("%s::unable to register ceetmFq functions\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	ceetm_dbg("%s::registered ceetmFq functions\n", __FUNCTION__);
	return CEETM_SUCCESS;
}

int ceetm_init_cq_plcr(void)
{
	uint32_t ii;
	uint32_t jj;
	uint32_t fm_index =0,profile = CDX_EGRESS_MIN_CQ_PROFILE;
	struct ceetm_chnl_info *chinfo;
	struct classque_info *cqinfo;
	void *pcd_handle;

	chinfo = &qm_chnl_info[0];
	pcd_handle = dpa_get_pcdhandle(fm_index);

	if (pcd_handle == NULL) {
		ceetm_err("%s::no pcd handle for fm_index %d\n",
			 __FUNCTION__, fm_index);
		return CEETM_FAILURE;
	}
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		cqinfo = &chinfo->cq_info[0];
		chinfo->pcd_handle = pcd_handle;
		for (jj = 0; jj < MAX_SCHEDULER_QUEUES; jj++) {
			if(ceetm_create_cq_policer_profiles(chinfo->pcd_handle,cqinfo,profile))
				return CEETM_FAILURE;
			cqinfo++;
			profile++;
		}
		chinfo++;
	}
	return CEETM_SUCCESS;
}

#ifdef CEETM_USE_CONG_STATE_CHANGE_NOTIFICATION 
static void ceetm_cscn_handler(struct qm_ceetm_ccg *p, void *cb_ctx, int congested)
{
	struct ceetm_fq *ceetm_fq = (struct ceetm_fq *)cb_ctx;
  
	/* Update the congestion state */
	if(ceetm_fq) {
		ceetm_dbg("%s::state %d\n", __FUNCTION__, congested); 
		ceetm_fq->congested = congested; 	
	} else 
		ceetm_err("%s::ceetm fq congestion state %d\n", __FUNCTION__, congested);
}
#endif

int ceetm_set_default_cq_policer_profile(void *pcd_handle, struct classque_info *cqinfo)
{
	void *handle;
	t_FmPcdPlcrProfileParams Params;


	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = cqinfo->pp_handle;

	/*init default cir and pir values */
	Params.nonPassthroughAlgParams.committedInfoRate = DEFAULT_CQ_CIR_VALUE;
	Params.nonPassthroughAlgParams.peakOrExcessInfoRate = DEFAULT_CQ_PIR_VALUE;

	ceetm_cq_policer_fill_defaults(&Params);

        handle = FM_PCD_PlcrProfileSet(pcd_handle, &Params);
        if (!handle) {
		printk("%s::unable to set default values for cq queue %p\n",
			__FUNCTION__, cqinfo);
		return ERR_QM_INGRESS_SET_PROFILE_FAILED;
        }
	/* init default cir and pir values */
	cqinfo->shaper_rate = DEFAULT_CQ_CIR_VALUE;
#ifdef DEVMAN_DEBUG
	printk("%s::plcr profile set to default for cd queue %p, handle %p\n",
		 __FUNCTION__,cqinfo, handle);
#endif
	return CEETM_SUCCESS;
}

int ceetm_reset_qos(struct tQM_context_ctl *qm_ctx)
{
	uint32_t ii;
	uint32_t jj;
	struct qm_ceetm_rate token;
	uint64_t rate;

	/* turn off port shaper */
	/* set limits very high, disable shaper */
	qm_ctx->shaper_info.token_cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
	qm_ctx->shaper_info.token_cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	qm_ctx->shaper_info.bsize = CEETM_DEFA_BSIZE;
	qm_ctx->shaper_info.enable = 0;
	if (qman_ceetm_tokenrate2bps(&qm_ctx->shaper_info.token_cr, &rate, 0)) {
		ceetm_err("%s::qman_ceetm_tokenrate2bps failed\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	qm_ctx->shaper_info.rate = rate;
	token.whole = 0;
	token.fraction = 0;
	ceetm_dbg("%s::turning port shaper off\n", __FUNCTION__); 
	if (ceetm_program_port_shaper(qm_ctx, &qm_ctx->shaper_info.token_cr,
		&token, qm_ctx->shaper_info.bsize)) {
		ceetm_err("%s:ceetm_program_shaper failed \n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		struct ceetm_chnl_info *qm_channel;
		struct qm_ceetm_channel *channel;
		struct classque_info *cqinfo;
		uint32_t priority;

		/* program all mapped channels */
		if (qm_ctx->chnl_map & (1 << ii)) {

			qm_channel = &qm_chnl_info[ii];
			channel = qm_channel->channel;
			/* disable channel shaper */
			qm_channel->wbfq_priority = CEETM_DEFA_WBFQ_PRIORITY;
			qm_channel->wbfq_chshaper = 0;
			qm_channel->shaper_info.token_cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
		        qm_channel->shaper_info.token_cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
			qm_channel->shaper_info.bsize = CEETM_DEFA_BSIZE;
			qm_channel->shaper_info.rate = rate;
			qm_channel->shaper_info.enable = 0;
			priority = GET_CEETM_PRIORITY(qm_channel->wbfq_priority);
			ceetm_dbg("%s::cfg prio %d, ceetm prio %d\n", __FUNCTION__,
				qm_channel->wbfq_priority, priority);
			if(qman_ceetm_channel_set_group(channel, 0, priority, priority)) {
				ceetm_err("%s::qman_ceetm_channel_set_group failed\n", __FUNCTION__);
				return CEETM_FAILURE;
			}
			ceetm_dbg("%s::turning channel %d shaper off\n", __FUNCTION__, ii); 
			if (ceetm_program_channel_shaper(qm_channel, &qm_channel->shaper_info.token_cr, 
				&qm_channel->shaper_info.token_cr, qm_channel->shaper_info.bsize)) {
				ceetm_err("%s:ceetm_program_shaper failed \n", __FUNCTION__);
				return CEETM_FAILURE;
			}
			/* program default weights, depths and policer profiles on all class queues */
			cqinfo = &qm_channel->cq_info[0];
			for (jj = 0; jj < MAX_SCHEDULER_QUEUES; jj++) {
  				struct qm_ceetm_weight_code weight_code;

				if (!jj) {
					if (qman_ceetm_ratio2wbfs(DEFAULT_CQ_DEPTH, 1, &weight_code, 0)) {
						ceetm_err("%s::Failed to convert weight %d\n",
							__FUNCTION__, cqinfo->weight);
						return CEETM_FAILURE;
					}
				}
				cqinfo->qdepth = DEFAULT_CQ_DEPTH;
				ceetm_dbg("%s::resetting que depth on class queue %d\n", __FUNCTION__, ii); 
				if (ceetm_cfg_td_on_class_queue(qm_channel, jj, cqinfo->qdepth)) {
					ceetm_err("%s::ceetm_cfg_ccg_to_class_queue failed on chnl %d\n", 
							__FUNCTION__, ii);
					return CEETM_FAILURE;
				}
				if (jj >= NUM_PQS) {
					/* wbfq */
					/* reset weight */
					/* Set the Queue Weight */
					cqinfo->weight = DEFAULT_WBFQ_WEIGHT;
					ceetm_dbg("%s::resetting weight on classque %d\n", __FUNCTION__, jj);
					if (qman_ceetm_set_queue_weight(cqinfo->cq, &weight_code)) {
						ceetm_err("%s::qman_ceetm_set_queue_weight failed\n", __FUNCTION__);
						return CEETM_FAILURE;
					}
					/* turn off class que shapers */
					if (qman_ceetm_channel_set_group_cr_eligibility(channel, 0, 0)) {
						ceetm_err("%s::Failed to set group cr eligibility"
							"of cq %d chnl %d\n", __FUNCTION__, jj, ii);			
						return CEETM_FAILURE;
					}
					if (qman_ceetm_channel_set_group_er_eligibility(channel, 0, 1)) {
						ceetm_err("%s::Failed to set group er eligibility" 
							"of cq %d chnl %d\n", __FUNCTION__, jj, ii);			
						return CEETM_FAILURE;
					}
				} else {
					cqinfo->ch_shaper_enable = 0;
					/* priority que */
					/* Set CR eligibility */
					ceetm_dbg("%s::resetting CR eligibility on cq %d\n", __FUNCTION__, jj);
					if (qman_ceetm_channel_set_cq_cr_eligibility(qm_channel->channel, jj, 0)) {
						ceetm_err("%s::Failed to set cr eligibility of cq %d\n", 
							__FUNCTION__, jj);
						return CEETM_FAILURE;
					}
					ceetm_dbg("%s::resetting ER eligibility\n", __FUNCTION__);
					/* Set ER eligibility */
					ceetm_dbg("%s::resetting ER eligibility on cq %d\n", __FUNCTION__, jj);
					if (qman_ceetm_channel_set_cq_er_eligibility(qm_channel->channel, jj, 1)) {
						ceetm_err("%s::Failed to set er eligibility of cq %d\n", 
							__FUNCTION__, jj);
						return CEETM_FAILURE;
					}
				}
				ceetm_set_default_cq_policer_profile(qm_channel->pcd_handle,cqinfo);
				cqinfo->cq_shaper_enable = DISABLE_POLICER;
				cqinfo++;
			}
		}		
	}
	return CEETM_SUCCESS;
}

int ceetm_enable_or_disable_qos(struct tQM_context_ctl *qm_ctx, uint32_t oper)
{
	struct qm_ceetm_rate token;
	struct ceetm_chnl_info *chnl_ctx;
	uint32_t ii;

	/* if context was notconfigured fully return error */
	if (!qm_ctx->chnl_map)
		return QOS_ENERR_NOT_CONFIGURED;
	if (oper) {
		if (!qm_ctx->qos_enabled) {

			/* initialize lni */
			if (ceetm_setup_lni(qm_ctx)) {
				ceetm_err("%s:ceetm_setup_lni failed \n", __FUNCTION__);
				return QOS_ENERR_IO;
			}
				
			token.whole = 0;
			token.fraction = 0;
			/* configure all shapers as per configuration in the context */
			/* program lni, port shaper */
			if (ceetm_program_port_shaper(qm_ctx, &qm_ctx->shaper_info.token_cr,
						&token,
						qm_ctx->shaper_info.bsize)) {
				ceetm_err("%s:ceetm_program_shaper failed \n", __FUNCTION__);
				return QOS_ENERR_IO;
			}
			for (ii = 0; ii < NUM_CHANNEL_SHAPERS; ii++) {
				if (qm_ctx->chnl_map & (1 << ii)) {
					chnl_ctx = &qm_chnl_info[ii];
					/* configure channel shaper */
					if (!chnl_ctx->shaper_info.enable) {
						token.whole = CEETM_TOKEN_WHOLE_MAXVAL;
						token.fraction = CEETM_TOKEN_FRAC_MAXVAL;
					}	
					if (ceetm_program_channel_shaper(chnl_ctx, &chnl_ctx->shaper_info.token_cr,
							&token,
							chnl_ctx->shaper_info.bsize)) {
						ceetm_err("%s:ceetm_program_shaper failed \n", __FUNCTION__);
						return QOS_ENERR_IO;
					}
				}
			}
			ceetm_dbg("%s::calling qman_sp_enable_ceetm_mode sp %p\n", __FUNCTION__,
				qm_ctx->lni->sp);
			
			if (qman_sp_enable_ceetm_mode(qm_ctx->lni->sp->dcp_idx, 
					qm_ctx->lni->sp->idx)) {
				ceetm_err("%s:qman_sp_enable_ceetm_mode failed \n", __FUNCTION__);
				return QOS_ENERR_IO;
			} 
			dpa_enable_ceetm(qm_ctx->net_dev);
			qm_ctx->qos_enabled = 1;
			ceetm_dbg("%s::CEETM enabled on iface %s\n", __FUNCTION__,
				qm_ctx->iface_info->name);
		} else {
			ceetm_dbg("%s::already enabled\n",__FUNCTION__);
		}
	} else {
		if (qm_ctx->qos_enabled) {
			
			/* disable port shaper */
			token.whole = CEETM_TOKEN_WHOLE_MAXVAL;
			token.fraction = CEETM_TOKEN_FRAC_MAXVAL;
			if (ceetm_program_port_shaper(qm_ctx, &token, &token, CEETM_DEFA_BSIZE)) {
				ceetm_err("%s:ceetm_program_shaper failed \n", __FUNCTION__);
				return QOS_ENERR_IO;
			}
			/* disable channel shapers */
			for (ii = 0; ii < NUM_CHANNEL_SHAPERS; ii++) {
				if (qm_ctx->chnl_map & (1 << ii)) {
					chnl_ctx = &qm_chnl_info[ii];
					if (ceetm_program_channel_shaper(chnl_ctx, &token, &token, CEETM_DEFA_BSIZE)) {
						ceetm_err("%s:ceetm_program_shaper failed \n", __FUNCTION__);
						return QOS_ENERR_IO;
					}
				}
			}
			qm_ctx->qos_enabled = 0;
		} else {
			ceetm_dbg("%s::already disabled\n",__FUNCTION__);
		}
	}
	return CEETM_SUCCESS;
}


static void display_shaper_config(PQosShaperConfigCommand cfg)
{
	ceetm_dbg("%s::flags %x size %ld\n", __FUNCTION__, cfg->cfg_flags,
			sizeof(QosShaperConfigCommand));
	if (cfg->cfg_flags & PORT_SHAPER_CFG) {
		ceetm_dbg("port shaper configuration iface %s::\n", cfg->ifname);
	} else {
		ceetm_dbg("channel shaper configuration:: channel %d\n", cfg->channel_num);
	}
	if (cfg->enable == SHAPER_ON)
		ceetm_dbg("shaper enabled\n");
	else {
		if (cfg->enable == SHAPER_OFF)
			ceetm_dbg("shaper disabled\n");
	}
	if (cfg->cfg_flags & SHAPER_CFG_VALID) {
		ceetm_dbg("rate %d, bucketsize %d\n",
			cfg->rate, cfg->bsize);
	}
}

static void display_wbfq_config(PQosWbfqConfigCommand cfg)
{
	ceetm_dbg("channel %d flags %x\n", cfg->channel_num, cfg->cfg_flags);
	if (cfg->cfg_flags & WBFQ_PRIORITY_VALID) {
		ceetm_dbg("QBFQ group priority %d\n", cfg->priority);
	}
}

int ceetm_configure_shaper(void *cmd)
{
	PQosShaperConfigCommand cfg;
	struct tQM_context_ctl *qm_ctx;
	cfg = (PQosShaperConfigCommand)cmd;

	display_shaper_config(cfg);
	if (cfg->cfg_flags & PORT_SHAPER_CFG) {
		struct cdx_port_info *port_info;
	
		/* port shaper */
		port_info = get_dpa_port_info(cfg->ifname);
		if (port_info) {
			qm_ctx = QM_GET_CONTEXT(port_info->portid);
		} else {
			ceetm_err("%s::unable to get context for port\n", __FUNCTION__);
			return CEETM_FAILURE;
		}	
		if (ceetm_cfg_shaper(qm_ctx, PORT_SHAPER_TYPE, cfg)) {
			ceetm_err("%s::ceetm_cfg_shaper failed for port\n", __FUNCTION__);
			return CEETM_FAILURE;
		}
	} else {
		struct ceetm_chnl_info *chnl_info;

		if (cfg->channel_num >= CDX_CEETM_MAX_CHANNELS) {
			ceetm_err("%s::invalid channel number\n", __FUNCTION__);
			return CEETM_FAILURE;
		}
		chnl_info = &qm_chnl_info[cfg->channel_num];
		/* channel shaper */
		if (ceetm_cfg_shaper(chnl_info, CHANNEL_SHAPER_TYPE, cfg)) {
			ceetm_err("%s::ceetm_cfg_shaper failed for channel\n", __FUNCTION__);
			return CEETM_FAILURE;
		}
	}
	return CEETM_SUCCESS;
}

int ceetm_configure_cq(void *cmd)
{
	PQosCqConfigCommand cfg;
	uint32_t ceetm_quenum;
	struct ceetm_chnl_info *chnl_ctx;

	cfg = (PQosCqConfigCommand)cmd;
	if (cfg->channel_num >= CDX_CEETM_MAX_CHANNELS) {
		ceetm_err("%s::invalid channel number %d\n", __FUNCTION__, cfg->channel_num);
		return CEETM_FAILURE;
	}

	/* check queue number */
	if (cfg->quenum >= NUM_CLASS_QUEUES) {
		ceetm_err("%s::invalid channel number %d\n", __FUNCTION__, cfg->channel_num);
		return CEETM_FAILURE;
	}
	chnl_ctx = &qm_chnl_info[cfg->channel_num];

	if (cfg->cfg_flags & CQ_RATE_VALID) {
		return ceetm_configure_cq_policer_profiles(&chnl_ctx->cq_info[cfg->quenum],
							chnl_ctx->pcd_handle,
							cfg->cq_shaper_on,cfg->shaper_rate);
	}
	/* adjust quenum for strict priority types */
	ceetm_quenum = chnl_ctx->cq_info[cfg->quenum].ceetm_idx;
	ceetm_dbg("%s::channel %d, cfg que %d, ceetm que %d\n", __FUNCTION__,
		cfg->channel_num, cfg->quenum, ceetm_quenum);
		
	/* qdepth appliable to both queue types */
	if (cfg->cfg_flags & CQ_TDINFO_VALID) {
        	if(ceetm_cfg_td_on_class_queue(chnl_ctx, ceetm_quenum, cfg->tdthresh))
                        return CEETM_FAILURE;
		chnl_ctx->cq_info[cfg->quenum].qdepth = cfg->tdthresh;
	}
	if (cfg->cfg_flags & CQ_WEIGHT_VALID) {
		struct qm_ceetm_weight_code weight_code;
		/* weight appliable to WBFQ */
		if (ceetm_quenum < CEETM_WBFS_START) 
			return CEETM_FAILURE;
		/* Set the Queue Weight */
		if (qman_ceetm_ratio2wbfs(cfg->weight, 1, &weight_code, 0)) {
			ceetm_err("%s::invalid value %d for que weight\n", __FUNCTION__,
				cfg->weight);
			return CEETM_FAILURE;
		}
		if (qman_ceetm_set_queue_weight(chnl_ctx->cq_info[cfg->quenum].cq, &weight_code)) {
			ceetm_err("%s::qman_ceetm_set_queue_weight failed\n", __FUNCTION__);
			return CEETM_FAILURE;
		}
		chnl_ctx->cq_info[cfg->quenum].weight = cfg->weight;
	}
	if (cfg->cfg_flags & CQ_SHAPER_CFG_VALID) {

		uint32_t enable;
		struct qm_ceetm_channel *channel;
		channel = chnl_ctx->channel;
		if (cfg->ch_shaper_en)
			enable = 1;
		else 
			enable = 0;
		if (ceetm_quenum  < CEETM_WBFS_START) {
			ceetm_dbg("%s::Setting shaper on prio queues\n", __FUNCTION__);
			/* Set CR eligibility */
			if (qman_ceetm_channel_set_cq_cr_eligibility(channel, ceetm_quenum, enable)) {
				ceetm_err("%s::Failed to set cr eligibility of cq %d chnl %p(%d)\n", __FUNCTION__,
					cfg->quenum, channel, channel->idx);			
				return CEETM_FAILURE;
			}
			/* Set ER eligibility */
			if (qman_ceetm_channel_set_cq_er_eligibility(channel, ceetm_quenum, (enable ^ 1))) {
				ceetm_err("%s::Failed to set er eligibility of cq %d chnl %p(%d)\n", __FUNCTION__,
					cfg->quenum, channel, channel->idx);			
				return CEETM_FAILURE;
			}
		}
		chnl_ctx->cq_info[cfg->quenum].ch_shaper_enable = enable;
	}
	return CEETM_SUCCESS;
}

int ceetm_assign_chnl(struct tQM_context_ctl *qm_ctx, uint32_t channel_num)
{
	uint32_t ii;
	struct ceetm_chnl_info *chnl_ctx;
	struct qm_ceetm_channel *channel;
	struct qm_ceetm_lni *lni;
	struct qm_mcc_ceetm_mapping_shaper_tcfc_config config_opts;

	if (channel_num >= CDX_CEETM_MAX_CHANNELS) {
		ceetm_err("%s::invalid channel number %d\n", __FUNCTION__,
			channel_num);
		return CEETM_FAILURE;
	}
	chnl_ctx = &qm_chnl_info[channel_num];
	if (chnl_ctx->qm_ctx) {
		ceetm_err("%s::channel number %d already assigned to iface %s\n", 
			__FUNCTION__, channel_num, qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}
	channel = chnl_ctx->channel;
	lni = qm_ctx->lni;
	ceetm_dbg("%s::assigning channel %d(%d) to iface %s\n", __FUNCTION__, 
			channel_num, chnl_ctx->idx, qm_ctx->iface_info->name);
	chnl_ctx->qm_ctx = qm_ctx;
	memset(&config_opts, 0, sizeof(struct qm_mcc_ceetm_mapping_shaper_tcfc_config));
	channel->dcp_idx = lni->dcp_idx;
	channel->lni_idx = lni->idx;
	list_add_tail(&channel->node, &lni->channels);
	config_opts.cid = cpu_to_be16(CEETM_COMMAND_CHANNEL_MAPPING |
				channel_num);
	config_opts.dcpid = lni->dcp_idx;
	config_opts.channel_mapping.map_lni_id = lni->idx;
	config_opts.channel_mapping.map_shaped = 1;
	if (qman_ceetm_configure_mapping_shaper_tcfc(&config_opts)) {
		ceetm_err("%s::Can't map channel %d for LNI on %s\n", __FUNCTION__, 
			channel_num, qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}
	qm_ctx->chnl_map |= (1 << chnl_ctx->idx);
	ceetm_dbg("%s::lni %d, dcp %d, chnl_map %x\n", __FUNCTION__, lni->idx, lni->dcp_idx, qm_ctx->chnl_map);
	/* if qos is enabled on port and channel shaper is on program values into shaper */

	for (ii = 0; ii < NUM_CLASS_QUEUES; ii++) {
		chnl_ctx->cq_info[ii].ceetmfq.net_dev = qm_ctx->net_dev;
	}
	return CEETM_SUCCESS;
}

/*
 * This function enable/disable dscp fq mapping on corresponding interface QM ctx for *
 * slow path, for fast path it updates in muRam. In SUCCESS case returns CEETM_SUCCESS*
 * In failure case it returns CEETM_FAILURE.                                          *
*/
int ceetm_enable_disable_dscp_fq_map(struct tQM_context_ctl *qm_ctx, uint8_t status) 
{
#ifdef ENABLE_EGRESS_QOS	
	if (status && qm_ctx->dscp_fq_map)
	{
		ceetm_err("dscp_fq_map is already enabled:\n");
		return CEETM_SUCCESS;
	}
	if ((!status) && (!qm_ctx->dscp_fq_map))
	{
		ceetm_err("dscp_fq_map is already disabled:\n");
		return CEETM_SUCCESS;
	}
	if (status)
	{
		if (enable_dscp_fqid_map(qm_ctx->port_info->portid))
		{
			ceetm_err("failed to enable dscp fqid mapping for port %s\n", qm_ctx->iface_info->name);
			return CEETM_FAILURE;
		}
		if (qm_ctx->dscp_fq_map)
		{
			ceetm_err("earlier dscp fqid mapping disable not proper, do disable again, before this enable.\n");
			return CEETM_FAILURE;
		}
		/* create memory for dscp fq map*/
		if ((qm_ctx->dscp_fq_map = kcalloc(1, sizeof(struct qm_dscp_fq_map), GFP_KERNEL)) == NULL)
		{
			ceetm_err("failed to create memory for dscp fq map table for port %s\n",
									qm_ctx->iface_info->name);		
			if (disable_dscp_fqid_map(qm_ctx->port_info->portid))
				ceetm_err("failed to disable dscp fqid mapping for port %s\n", 
									qm_ctx->iface_info->name);
			return CEETM_FAILURE;
		}
	}
	else
	{
		if (disable_dscp_fqid_map(qm_ctx->port_info->portid))
		{
			ceetm_err("failed to disable dscp fqid mapping for port %s\n", qm_ctx->iface_info->name);
			return CEETM_FAILURE;
		}
		/* delete memory for dscp fq map*/
		kfree(qm_ctx->dscp_fq_map);
		qm_ctx->dscp_fq_map = NULL;
	}
#endif
	return CEETM_SUCCESS;
}

/*
 * This function unmaps the dscp fq mapping in corresponding interface QM ctx
 * for slow path.  It does unmapping only for slow path case. On success returns
 * CEETM_SUCCESS otherwise CEETM_FAILURE.
*/
static int dscp_fq_unmap(struct tQM_context_ctl *qm_ctx, uint8_t dscp)
{
	if (!qm_ctx->dscp_fq_map)
	{
		ceetm_err("dscp to fq map is not enabled on this interface <%s>\n", qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}
	qm_ctx->dscp_fq_map->dscp_fq[dscp] = NULL;

	return CEETM_SUCCESS;
}

/*
 * This function reset all the dscp fq mappings on that interface for fast path.
 * It does for fast path only. It returns always CEETM_SUCCESS.
*/
int reset_all_dscp_fq_map_ff(cdx_dscp_fqid_t *muram_dscp_fqid_map)
{
	int index;

	for (index = 0; index < MAX_DSCP; index++)
	{
		/* In this function not using functions related to copy content from muram to ddr*/
		/* Do the modifications on ddr memory and write back them to muram memory. */
		/* Basically these functions used to avoid issue with 16 bit instruction with muram memory address.*/
		/* But in this structure all variables are 32 bit, so it is not required. */
		muram_dscp_fqid_map->fqid[index] = 0;
	}

	return CEETM_SUCCESS;
}

/*
 * This function resets the specific dscp value fq mapping on corresponding interface.
 * this is for fastpath. It always returns CEETM_SUCCESS>
*/
int reset_dscp_fq_map_ff(cdx_dscp_fqid_t *muram_dscp_fqid_map, uint8_t dscp)
{
	/* In this function not using functions related to copy content from muram to ddr*/
	/* Do the modifications on ddr memory and write back them to muram memory. */
	/* Basically these functions used to avoid issue with 16 bit instruction with muram memory address.*/
	/* But in this structure all variables are 32 bit, so it is not required. */
	/* Resetting the dscp fqid */
	muram_dscp_fqid_map->fqid[dscp] = 0;

	return CEETM_SUCCESS;
}

/*
 * This function umap dscp fa mapping in fast path. *
 * It returns CEETM_SUCCESS in success case otherwise returns CEETM_FAILURE *
*/
static int dscp_fq_unmap_ff(struct tQM_context_ctl *qm_ctx, uint8_t dscp)
{
	cdx_dscp_fqid_t	*dscp_fqid_map;

	if ((dscp_fqid_map = get_dscp_fqid_map(qm_ctx->port_info->portid)) == NULL)
		return CEETM_FAILURE;

	if (reset_dscp_fq_map_ff(dscp_fqid_map, dscp))
		return CEETM_FAILURE;

	return CEETM_SUCCESS;
}

/*
 * This function umap dscp fa mapping in slow path. *
 * It returns CEETM_SUCCESS in success case otherwise returns CEETM_FAILURE *
*/
int ceetm_dscp_fq_unmap(struct tQM_context_ctl *qm_ctx, uint8_t dscp)
{
	if (dscp_fq_unmap(qm_ctx, dscp))
	{
		ceetm_err("dscp to fq unmap is failed on interface <%s>\n", qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}
	if (dscp_fq_unmap_ff(qm_ctx, dscp))
	{
		ceetm_err("%s::%d dscp to fq unmap is failed on interface <%s>\n", 
				__FUNCTION__, __LINE__, qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}
	return CEETM_SUCCESS;
}

/*
 * This function add one dscp fq mapping in slow path. It returns CEETM_SUCCESS
 * in success case otherwise returns CEETM_FAILURE.
*/
static int add_dscp_fq_map(struct tQM_context_ctl *qm_ctx, uint8_t dscp, struct qman_fq *egress_fq)
{
	if (!qm_ctx->dscp_fq_map)
	{
		ceetm_err("dscp to fq map is not enabled on this interface <%s>\n", qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}
	qm_ctx->dscp_fq_map->dscp_fq[dscp] = egress_fq;

	return CEETM_SUCCESS;
}

/*
 * This function add one dscp fq mapping in fast path. It returns CEETM_SUCCESS
 * in success case otherwise returns CEETM_FAILURE.
*/
static int add_dscp_fq_map_ff(struct tQM_context_ctl *qm_ctx, uint8_t dscp, struct qman_fq *egress_fq)
{
	cdx_dscp_fqid_t	*dscp_fqid_map;

	if ((dscp_fqid_map = get_dscp_fqid_map(qm_ctx->port_info->portid)) == NULL)
		return CEETM_FAILURE;

	dscp_fqid_map->fqid[dscp] = cpu_to_be32(egress_fq->fqid);

	return CEETM_SUCCESS;
}

/*
 * This function finds the CEETM FQ using channel and classqueue corresponding interface. It maps *
 * the dscp fq in slow path and fast path.  It returns CEETM_SUCCESS in success case otherwise *
 *  returns CEETM_FAILURE. *
*/
int ceetm_dscp_fq_map(struct tQM_context_ctl *qm_ctx, uint8_t dscp, uint8_t channel_num, uint8_t clsqueue_num)
{
	struct qman_fq *egress_fq;

		/* slow path get egress fq*/
	egress_fq = ceetm_get_egressfq(qm_ctx, channel_num, clsqueue_num, 0);
	if (!egress_fq)
	{
		ceetm_err("Failed to find egress fq for channel %d and class queue %d on %s\n", 
				channel_num, clsqueue_num, qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}

	if (add_dscp_fq_map(qm_ctx, dscp, egress_fq))
	{
		ceetm_err("Failed to add dscp %d fq %d map on %s\n", 
				dscp, egress_fq->fqid, qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}

		/* fast path get egress fq*/
	egress_fq = ceetm_get_egressfq(qm_ctx, channel_num, clsqueue_num, 1);
	if (!egress_fq)
	{
		ceetm_err("Failed to find egress fq for channel %d and class queue %d on %s\n", 
				channel_num, clsqueue_num, qm_ctx->iface_info->name);
		if (dscp_fq_unmap(qm_ctx, dscp))
			ceetm_err("dscp to fq unmap is failed on interface <%s>\n", qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}
	if (add_dscp_fq_map_ff(qm_ctx, dscp, egress_fq))
	{
		ceetm_err("Failed to add dscp %d fq %d map on %s\n", 
				dscp, egress_fq->fqid, qm_ctx->iface_info->name);
		if (dscp_fq_unmap(qm_ctx, dscp))
			ceetm_err("dscp to fq unmap is failed on interface <%s>\n", qm_ctx->iface_info->name);
		return CEETM_FAILURE;
	}

	return CEETM_SUCCESS;
}

/*
 * This function returns all the DSCP FQ mapping status on that interface, if it is   *
 * enable it returns all the dscp mapped fq details. It returns always CEETM_SUCCESS. *
*/
int ceetm_get_dscp_fq_map(struct tQM_context_ctl *qm_ctx, PQosIfaceDscpFqidMapCommand cmd)
{
	cdx_dscp_fqid_t	*dscp_fqid_map;
	uint16_t index;

	if ((dscp_fqid_map = get_dscp_fqid_map(qm_ctx->port_info->portid)) != NULL)
	{
		for (index = 0; index < MAX_DSCP; index++)
			cmd->fqid[index] = be32_to_cpu(dscp_fqid_map->fqid[index]);
	}
	else
	{
		ceetm_err("DSCP to fqmap is not enabled on this interface %s\n", qm_ctx->iface_info->name);
		memset(cmd->fqid, 0, sizeof(uint32_t)*MAX_DSCP);
	}

	return CEETM_SUCCESS;
}

int ceetm_configure_wbfq(void *cmd)
{
	struct ceetm_chnl_info *chnl_ctx;
	PQosWbfqConfigCommand cfg;
	struct qm_ceetm_channel *channel;
	uint32_t priority;

	cfg = (PQosWbfqConfigCommand)cmd;
	if (cfg->channel_num >= CDX_CEETM_MAX_CHANNELS) {
		ceetm_err("%s::invalid channel number\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	chnl_ctx = &qm_chnl_info[cfg->channel_num];	
	channel = chnl_ctx->channel;
	display_wbfq_config(cmd);
	priority = GET_CEETM_PRIORITY(cfg->priority);
	ceetm_dbg("%s::channel %d cfg prio %d, ceetm prio %d\n", __FUNCTION__,
				cfg->channel_num, cfg->priority, priority);
	if (cfg->cfg_flags & WBFQ_PRIORITY_VALID) {
		if(qman_ceetm_channel_set_group(channel, 0, priority, priority)) {
			ceetm_err("%s::qman_ceetm_channel_set_group failed\n", __FUNCTION__);
			return CEETM_FAILURE;
		}
		/* save it in the configuration */
		chnl_ctx->wbfq_priority = cfg->priority;
	}
	/* set shaper eligiblity */
	ceetm_dbg("%s::Setting shaper on wbfq queues\n", __FUNCTION__);
	if (cfg->cfg_flags & WBFQ_SHAPER_VALID) {
		if (qman_ceetm_channel_set_group_cr_eligibility(channel, 0, cfg->wbfq_chshaper)) {
			ceetm_err("%s::Failed to set group cr eligibility of wbfq chnl %p\n", __FUNCTION__,
					channel);
			return CEETM_FAILURE;
		}
		if (qman_ceetm_channel_set_group_er_eligibility(channel, 0, (cfg->wbfq_chshaper ^ 1))) {
			ceetm_err("%s::Failed to set group er eligibility of wbfq chnl %p\n", __FUNCTION__,
					channel);
			return CEETM_FAILURE;
		}
	}
	/* save it in the configuration */
	chnl_ctx->wbfq_chshaper = cfg->wbfq_chshaper;
	return CEETM_SUCCESS;
}

/* return current configuration for the port, queue */
int ceetm_get_qos_cfg(struct tQM_context_ctl *ctx, pQosQueryCmd query)
{
	uint32_t ii;
	struct shaper_info *shaper_info;
	struct ceetm_chnl_info *chnl_info;

	query->if_qos_enabled = ctx->qos_enabled;
	shaper_info = &ctx->shaper_info;
	query->shaper_enabled = shaper_info->enable;
	if (query->shaper_enabled) { 
		/* port channel shaper config */
		query->rate = (shaper_info->rate / 1000);
		query->bsize = shaper_info->bsize;
		ceetm_dbg("port shaper enabled:: rate %d, bsize %d\n", 
			query->rate, query->bsize);
	} else {
		ceetm_dbg("port shaper disabled\n");
	}
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {	
		if (ctx->chnl_map & (1 << ii)) {
			chnl_info = &qm_chnl_info[ii];
			query->chnl_shaper_info[ii].valid = 1;
			query->chnl_shaper_info[ii].shaper_enabled = 
				chnl_info->shaper_info.enable;
			if (chnl_info->shaper_info.enable) {
				query->chnl_shaper_info[ii].rate = (chnl_info->shaper_info.rate / 1000);
				query->chnl_shaper_info[ii].bsize = chnl_info->shaper_info.bsize;
			}
		} else
			query->chnl_shaper_info[ii].valid = 0;
	}
	return CEETM_SUCCESS;
}

/* get class que statistics from hardware */
int ceetm_get_cq_query(pQosCqQueryCmd cmd)
{
	uint32_t quenum;
	uint64_t pkt_count;
	uint64_t byte_count;
	struct qm_ceetm_cq *cq;
	struct qm_ceetm_ccg *ccg;
	struct ceetm_chnl_info *chnl_ctx;
	struct classque_info *cq_info;

	if (cmd->channel_num >= CDX_CEETM_MAX_CHANNELS) {
		ceetm_err("%s::invalid channel number %d\n", __FUNCTION__, cmd->channel_num);			
		return CEETM_FAILURE;
	}
	quenum = cmd->queuenum;
	if (quenum >= CDX_CEETM_MAX_QUEUES_PER_CHANNEL) { 
		ceetm_err("%s::invalid queue number %d\n", __FUNCTION__, quenum);			
		return CEETM_FAILURE;
	}
	chnl_ctx = &qm_chnl_info[cmd->channel_num];
	cq_info = &chnl_ctx->cq_info[quenum];	
	cmd->wbfq_priority = chnl_ctx->wbfq_priority;
	cmd->wbfq_chshaper = chnl_ctx->wbfq_chshaper;
	cmd->qdepth = cq_info->qdepth;
	cmd->fqid = cq_info->ceetmfq.egress_fq.fqid;
	if (quenum >= NUM_PQS) 
		cmd->weight = cq_info->weight;
	cmd->cq_ch_shaper = cq_info->ch_shaper_enable;
	cq = (struct qm_ceetm_cq *)cq_info->cq;
	ccg = (struct qm_ceetm_ccg *)cq_info->ccg;
	if (ceetm_get_fqcount(chnl_ctx, quenum, &cmd->frm_count)) {
		ceetm_err("%s::Failed to get fq count on que %d\n", __FUNCTION__, quenum);			
		return CEETM_FAILURE;
	}
	if (qman_ceetm_cq_get_dequeue_statistics(cq, cmd->clear_stats, &pkt_count, 
		&byte_count)) {
		ceetm_err("%s::Failed to get cq deque stats %d\n", __FUNCTION__, quenum);			
		return CEETM_FAILURE;
	}
	cmd->deque_pkts_high = (pkt_count >> 32);
	cmd->deque_pkts_lo = (pkt_count & 0xffffffff);
	cmd->deque_bytes_high = (byte_count >> 32);
	cmd->deque_bytes_lo = (byte_count & 0xffffffff);
	if (qman_ceetm_ccg_get_reject_statistics(ccg, cmd->clear_stats, &pkt_count, 
		&byte_count)) {
		ceetm_err("%s::Failed to get cq reject stats %d\n", __FUNCTION__, quenum);			
		return CEETM_FAILURE;
	}
	cmd->reject_pkts_high = (pkt_count >> 32);
	cmd->reject_pkts_lo = (pkt_count & 0xffffffff);
	cmd->reject_bytes_high = (byte_count >> 32);
	cmd->reject_bytes_lo = (byte_count & 0xffffffff);

	cmd->cq_shaper_on =  cq_info->cq_shaper_enable;
	cmd->cir          = cq_info->shaper_rate;

	if(cq_info->cq_shaper_enable)
		get_plcr_counter(cq_info->pp_handle, &cmd->counterval[0],cmd->clear_stats);

	return CEETM_SUCCESS;
}

#ifdef ENABLE_EGRESS_QOS
int ceetm_exit(void)
{
	/* deregister functions to return CEETM egress FQID */
	if (dpa_register_ceetm_get_egress_fq(NULL, NULL)) {
		ceetm_err("%s::unable to deregister ceetmFq functions\n", __FUNCTION__);
		return CEETM_FAILURE;
	}
	ceetm_dbg("%s::deregistered ceetmFq functions\n", __FUNCTION__);
	/*TODO : ceetm cleanup */
	/* 1. Channels creation cleanup (memory, channel)  */
	/* 2. class queue (ceetm ccg release, ceetm lfq, cq release) */
	/*TODO : ENABLE_EGRESS_QOS compilation flag cleanup */
	/* ENABLE_EGRESS_QOS compilation flag proper integration. */

	return CEETM_SUCCESS;
}
#endif
