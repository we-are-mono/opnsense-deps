/*
 * CDX CEETM egress QoS — FreeBSD port
 *
 * Ported from ASK/cdx-5.03.1/cdx_ceetm_app.c (NXP/Freescale).
 * Uses kernel qman_ceetm_* APIs from sys/dev/dpaa/qman_ceetm.c.
 *
 * Key differences from Linux:
 *   - Channel HW allocation deferred to ceetm_assign_chnl() time
 *     (kernel API requires LNI at channel_claim, Linux creates channels
 *      without LNI and maps later)
 *   - No dpa_register_ceetm_get_egress_fq / dpa_enable_ceetm — CEETM
 *     egress FQ lookup integrated into cdx_devman_freebsd.c
 *   - No skb-based ERN handler — stub
 *   - CQ policer profiles (FM_PCD_PlcrProfileSet) deferred
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <dev/dpaa/qman_ceetm.h>	/* MUST be first for real CEETM types */

#include "portdefs.h"
#include "cdx.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "cdx_common.h"

/*
 * CEETM_SUCCESS, CEETM_FAILURE, ceetm_err, ceetm_dbg are all defined
 * in cdx_ceetm_app.h (included above).  Linux printk/KERN_ERR and
 * smp_processor_id() mapped to FreeBSD equivalents by linux_compat.h.
 */

/* ================================================================
 * Static state — mirrors Linux qm_chnl_info[] array
 * ================================================================ */

static struct ceetm_chnl_info qm_chnl_info[CDX_CEETM_MAX_CHANNELS];

/*
 * Whether channels have been HW-initialised.  On Linux, ceetm_init_channels()
 * creates HW channels immediately.  On FreeBSD the kernel channel_claim API
 * requires an LNI, so HW init is deferred to ceetm_assign_chnl().  This flag
 * per-channel tracks whether HW resources exist.
 */
static uint8_t chnl_hw_created[CDX_CEETM_MAX_CHANNELS];

/* ================================================================
 * ceetm_get_egressfq — lookup CEETM egress FQ for a given channel+cq
 *
 * Called from cdx_get_txfq() (cdx_devman_freebsd.c) and internally.
 * ================================================================ */

struct qman_fq *ceetm_get_egressfq(void *ctx, uint32_t channel,
    uint32_t classque, uint32_t ff);

struct qman_fq *
ceetm_get_egressfq(void *ctx, uint32_t channel, uint32_t classque, uint32_t ff)
{
	struct ceetm_chnl_info *chnl_ctx;
	struct tQM_context_ctl *qm_ctx;
	struct qman_fq *fq;

	if (channel > CDX_CEETM_MAX_CHANNELS)
		return (NULL);
	if (classque >= CDX_CEETM_MAX_QUEUES_PER_CHANNEL)
		return (NULL);
	if (!channel) {
		qm_ctx = (struct tQM_context_ctl *)ctx;
		if (qm_ctx == NULL) {
			ceetm_err("invalid channel context\n");
			return (NULL);
		}
		/* get least prio channel on this interface */
		channel = (CDX_CEETM_MAX_CHANNELS - 1);
		while (channel > 0) {
			if (qm_ctx->chnl_map & (1 << channel))
				break;
			channel--;
		}
		ceetm_dbg("incoming channel reassigned as %u\n", channel);
	} else {
		channel--;
	}
	chnl_ctx = &qm_chnl_info[channel];
	fq = &chnl_ctx->cq_info[classque].ceetmfq.egress_fq;

	/*
	 * CQ policer profile embedding in FQID MSByte — deferred.
	 * When policer profiles are implemented, set pp_num in MSByte here.
	 */
	(void)ff;

	return (fq);
}

/* ================================================================
 * ceetm_get_dscp_fq — return DSCP-mapped FQ from qm_ctx
 * ================================================================ */

static struct qman_fq *
ceetm_get_dscp_fq(void *ctx, uint8_t dscp)
{
	struct tQM_context_ctl *qm_ctx = (struct tQM_context_ctl *)ctx;

	if (qm_ctx->dscp_fq_map == NULL)
		return (NULL);
	if (dscp >= MAX_DSCP) {
		ceetm_err("invalid dscp value %u on tx iface <%s>\n",
		    dscp, qm_ctx->iface_info->name);
		return (NULL);
	}
	return (qm_ctx->dscp_fq_map->dscp_fq[dscp]);
}

/* ================================================================
 * Internal shaper helpers
 * ================================================================ */

static int
ceetm_program_port_shaper(struct tQM_context_ctl *qm_ctx,
    struct qm_ceetm_rate *rate, struct qm_ceetm_rate *limit, uint32_t bsize)
{
	struct qm_ceetm_lni *lni;

	ceetm_dbg("port rate whole %x, fraction %x, limit whole %x, "
	    "fraction %x, bsize %u\n", rate->whole, rate->fraction,
	    limit->whole, limit->fraction, bsize);
	lni = qm_ctx->lni;
	if (qman_ceetm_lni_set_commit_rate(lni, rate, bsize)) {
		ceetm_err("qman_ceetm_lni_set_commit_rate failed\n");
		return (CEETM_FAILURE);
	}
	if (qman_ceetm_lni_set_excess_rate(lni, limit, bsize)) {
		ceetm_err("qman_ceetm_lni_set_excess_rate failed\n");
		return (CEETM_FAILURE);
	}
	ceetm_dbg("port shaper programmed\n");
	return (CEETM_SUCCESS);
}

static int
ceetm_program_channel_shaper(struct ceetm_chnl_info *chnl_ctx,
    struct qm_ceetm_rate *rate, struct qm_ceetm_rate *limit, uint32_t bsize)
{
	struct qm_ceetm_channel *channel;

	ceetm_dbg("channel rate whole %x, fraction %x, limit whole %x, "
	    "fraction %x, bsize %u\n", rate->whole, rate->fraction,
	    limit->whole, limit->fraction, bsize);
	channel = chnl_ctx->channel;
	if (qman_ceetm_channel_set_commit_rate(channel, rate, bsize)) {
		ceetm_err("qman_ceetm_channel_set_commit_rate failed\n");
		return (CEETM_FAILURE);
	}
	if (qman_ceetm_channel_set_excess_rate(channel, limit, bsize)) {
		ceetm_err("qman_ceetm_channel_set_excess_rate failed\n");
		return (CEETM_FAILURE);
	}
	ceetm_dbg("channel shaper programmed\n");
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_create_lni — allocate LNI and sub-portal for an interface
 * ================================================================ */

int
ceetm_create_lni(struct tQM_context_ctl *qm_ctx)
{
	int index;
	struct qm_ceetm_lni *lni;
	struct qm_ceetm_sp *sp;

	/* use idx as lower part of tx_channel_id */
	index = (qm_ctx->iface_info->eth_info.tx_channel_id & 0xf);
	ceetm_dbg("lni index %d\n", index);

	sp = NULL;
	lni = NULL;

	ceetm_dbg("claiming sp\n");
	if (qman_ceetm_sp_claim(&sp, qm_ctx->port_info->fm_index, index)) {
		ceetm_err("unable to claim sp_index %d\n", index);
		goto err_ret;
	}

	ceetm_dbg("claiming lni\n");
	if (qman_ceetm_lni_claim(&lni, qm_ctx->port_info->fm_index, index)) {
		ceetm_err("qman_ceetm_lni_claim failed\n");
		goto err_ret;
	}

	qm_ctx->lni = lni;
	qm_ctx->sp = sp;
	ceetm_dbg("allocated lni %p for index %u\n", lni, lni->idx);
	return (CEETM_SUCCESS);

err_ret:
	if (lni != NULL)
		qman_ceetm_lni_release(lni);
	if (sp != NULL)
		qman_ceetm_sp_release(sp);
	return (CEETM_FAILURE);
}

/* set up lni, disable shaping by default */
static int
ceetm_setup_lni(struct tQM_context_ctl *qm_ctx)
{
	struct shaper_info *shinfo;
	struct qm_ceetm_rate token_er;

	ceetm_dbg("setting lni,sp\n");
	if (qman_ceetm_sp_set_lni(qm_ctx->sp, qm_ctx->lni)) {
		ceetm_err("qman_ceetm_sp_set_lni failed\n");
		return (CEETM_FAILURE);
	}
	qm_ctx->lni->sp = qm_ctx->sp;

	/* enable lni shaper coupled */
	if (qman_ceetm_lni_enable_shaper(qm_ctx->lni, 1, CEETM_DEFA_OAL)) {
		ceetm_err("qman_ceetm_lni_enable_shaper failed\n");
		return (CEETM_FAILURE);
	}

	/* disable shaper by setting large values for port shaper */
	shinfo = &qm_ctx->shaper_info;
	shinfo->enable = 0;
	shinfo->token_cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
	shinfo->token_cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	token_er.whole = 0;
	token_er.fraction = 0;
	shinfo->bsize = CEETM_DEFA_BSIZE;

	if (ceetm_program_port_shaper(qm_ctx, &shinfo->token_cr, &token_er,
	    shinfo->bsize)) {
		ceetm_err("unable to program lni shaper, idx %u\n",
		    qm_ctx->lni->idx);
		return (CEETM_FAILURE);
	}
	ceetm_dbg("setup for lni %p, index %u complete\n",
	    qm_ctx->lni, qm_ctx->lni->idx);
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_cfg_shaper — enable/disable/configure port or channel shaper
 * ================================================================ */

static int
ceetm_cfg_shaper(void *ctx, uint32_t type, PQosShaperConfigCommand params)
{
	struct qm_ceetm_rate token_cr;
	struct qm_ceetm_rate token_er;
	struct shaper_info *shinfo;
	struct tQM_context_ctl *qm_ctx;
	struct ceetm_chnl_info *chnl_ctx;
	uint32_t cfg;
	uint32_t enable;

	cfg = 0;
	qm_ctx = NULL;
	chnl_ctx = NULL;
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
		if (qman_ceetm_bps2tokenrate((params->rate * 1000),
		    &token_cr, 0)) {
			ceetm_err("CR qman_ceetm_bps2tokenrate failed\n");
			return (CEETM_FAILURE);
		}
		ceetm_dbg("CR Rate %u whole %u fraction %u\n",
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
		token_cr = shinfo->token_cr;
		cfg = 1;
		enable = 1;
	} else if (params->enable == SHAPER_OFF) {
		token_cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
		token_cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
		cfg = 1;
		enable = 0;
	}

	if (cfg) {
		if (type == PORT_SHAPER_TYPE) {
			if (ceetm_program_port_shaper(qm_ctx, &token_cr,
			    &token_er, shinfo->bsize))
				return (CEETM_FAILURE);
		} else {
			if (ceetm_program_channel_shaper(chnl_ctx, &token_cr,
			    &token_er, shinfo->bsize))
				return (CEETM_FAILURE);
		}
	}
	shinfo->enable = enable;
	ceetm_dbg("CR and ER configured, enable %u\n", enable);
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_release_lni — release LNI + SP
 * ================================================================ */

int
ceetm_release_lni(void *handle)
{
	struct qm_ceetm_lni *lni;
	uint32_t lni_index;

	if (handle == NULL)
		return (CEETM_FAILURE);
	lni = (struct qm_ceetm_lni *)handle;
	lni_index = lni->idx;
	ceetm_dbg("releasing lni %p index %u\n", lni, lni_index);
	if (qman_ceetm_lni_release(lni) == 0) {
		if (qman_ceetm_sp_release(lni->sp)) {
			ceetm_err("sp release failed on lni idx %u\n",
			    lni_index);
			return (CEETM_FAILURE);
		}
	} else {
		ceetm_err("lni %u release failed\n", lni_index);
		return (CEETM_FAILURE);
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * CCG + tail-drop helpers
 * ================================================================ */

static int
ceetm_create_ccg_for_class_queue(struct ceetm_chnl_info *chnl_ctx,
    uint32_t classque)
{
	struct qm_ceetm_channel *channel;
	struct qm_ceetm_ccg *ccg;

	channel = chnl_ctx->channel;
	ceetm_dbg("claiming CCG for classque %u on channel %p\n",
	    classque, channel);
	if (qman_ceetm_ccg_claim(&ccg, channel,
	    chnl_ctx->cq_info[classque].ceetm_idx, NULL, NULL)) {
		ceetm_err("qman_ceetm_ccg_claim failed for channel %p\n",
		    channel);
		return (CEETM_FAILURE);
	}
	ceetm_dbg("CCG claimed ccg %p for class queue %u\n", ccg, classque);
	chnl_ctx->cq_info[classque].ccg = ccg;
	return (CEETM_SUCCESS);
}

static void
ceetm_num_to_2powN_multiple(uint32_t num_in, uint32_t *num, uint32_t *mul,
    uint32_t maxbits, uint32_t maxbits_mul)
{
	int ii;
	int msbbit;

	msbbit = 0;
	for (ii = 0; ii < (int)(sizeof(ii) * 8); ii++) {
		if (num_in & (1U << ii))
			msbbit = ii;
	}

	if ((uint32_t)msbbit < maxbits_mul) {
		*num = 0;
		*mul = num_in;
	} else {
		if ((uint32_t)msbbit < (maxbits_mul + (1 << maxbits) - 1)) {
			*num = msbbit - maxbits_mul + 1;
			*mul = num_in >> (*num);
		} else {
			*num = maxbits;
			*mul = (1 << maxbits_mul) - 1;
		}
	}
}

static int
ceetm_cfg_td_on_class_queue(struct ceetm_chnl_info *chnl_ctx,
    uint32_t index, uint32_t tdthresh)
{
	struct qm_ceetm_ccg *ccg;
	struct qm_mcc_ceetm_ccgr_config params;
	uint16_t mask;
	unsigned int uiNum, uiMul;

	memset(&params, 0, sizeof(params));
	mask = (QM_CEETM_CCGR_WE_TD_EN | QM_CEETM_CCGR_WE_MODE |
	    QM_CEETM_CCGR_WE_TD_MODE);

	if (!tdthresh) {
		params.ctl = QM_CEETM_CCGR_CTL_MODE;  /* frame count mode */
		/* td_en = 0, td_mode = 1, cscn_en = 0 */
		params.ctl |= QM_CEETM_CCGR_CTL_TD_MODE;
		params.td_thres = 0;
	} else {
		params.ctl = QM_CEETM_CCGR_CTL_MODE |
		    QM_CEETM_CCGR_CTL_TD_EN | QM_CEETM_CCGR_CTL_TD_MODE;
		ceetm_num_to_2powN_multiple(tdthresh, &uiNum, &uiMul, 5, 8);
		/* td_thres: Tn in upper bits, TA in lower bits */
		params.td_thres = htobe16((uiNum << 8) | (uiMul & 0xFF));
		mask |= QM_CEETM_CCGR_WE_TD_THRES;
	}

	ccg = (struct qm_ceetm_ccg *)chnl_ctx->cq_info[index].ccg;
	if (qman_ceetm_ccg_set(ccg, mask, &params)) {
		ceetm_err("unable to set ccg parameters\n");
		return (CEETM_FAILURE);
	}
	chnl_ctx->cq_info[index].qdepth = tdthresh;
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_create_cq — create CQ + LFQ + egress FQ for a class queue
 * ================================================================ */

static int
ceetm_create_cq(struct ceetm_chnl_info *chnl_ctx, uint32_t classque)
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
			ceetm_err("invalid value %u for channel index\n",
			    classque);
			return (CEETM_FAILURE);
		}
		type = CEETM_WBFQ_QUEUE;
	}
	ceetm_quenum = chnl_ctx->cq_info[classque].ceetm_idx;
	ceetm_dbg("channel %p chnl_idx %u, cq %u, ceetm_cq %u\n",
	    chnl_ctx, chnl_ctx->idx, classque, ceetm_quenum);
	channel = chnl_ctx->channel;
	cqinfo = &chnl_ctx->cq_info[classque];
	ccg = (struct qm_ceetm_ccg *)cqinfo->ccg;
	if (ccg == NULL) {
		ceetm_err("no CCG for class queue %u, chnl %p(%u)\n",
		    classque, channel, channel->idx);
		return (CEETM_FAILURE);
	}

	if (type == CEETM_PRIO_QUEUE) {
		ceetm_dbg("claiming prio class que\n");
		if (qman_ceetm_cq_claim(&cq, channel, ceetm_quenum, ccg)) {
			ceetm_err("failed to claim CQ %u for chnl %p(%u)\n",
			    classque, channel, channel->idx);
			return (CEETM_FAILURE);
		}
		cqinfo->ch_shaper_enable = 0;
		/* no CR eligibility */
		if (qman_ceetm_channel_set_cq_cr_eligibility(channel,
		    ceetm_quenum, 0)) {
			ceetm_err("failed to set cr eligibility of cq %u\n",
			    classque);
			goto err_ret;
		}
		/* Set ER eligibility, disabling shaping */
		if (qman_ceetm_channel_set_cq_er_eligibility(channel,
		    ceetm_quenum, 1)) {
			ceetm_err("failed to set er eligibility of cq %u\n",
			    classque);
			goto err_ret;
		}
	} else {
		struct qm_ceetm_weight_code weight_code;

		/* all wbfq cq are in a single group, GRP A */
		ceetm_dbg("claiming group A\n");
		if (qman_ceetm_cq_claim_A(&cq, channel, ceetm_quenum, ccg)) {
			ceetm_err("failed to claim CQ A for CH %u\n",
			    channel->idx);
			return (CEETM_FAILURE);
		}
		/* set shaper eligibility */
		if (qman_ceetm_channel_set_group_cr_eligibility(channel,
		    0, 0)) {
			ceetm_err("failed to set group cr eligibility\n");
			return (CEETM_FAILURE);
		}
		if (qman_ceetm_channel_set_group_er_eligibility(channel,
		    0, 1)) {
			ceetm_err("failed to set group er eligibility\n");
			return (CEETM_FAILURE);
		}

		/* Set the Queue Weight */
		cqinfo->weight = DEFAULT_WBFQ_WEIGHT;
		if (qman_ceetm_ratio2wbfs(DEFAULT_WBFQ_WEIGHT, 1,
		    &weight_code, 0)) {
			ceetm_err("failed to convert weight %u\n",
			    DEFAULT_WBFQ_WEIGHT);
			return (CEETM_FAILURE);
		}
		ceetm_dbg("setting weight\n");
		if (qman_ceetm_set_queue_weight(cq, &weight_code)) {
			ceetm_err("failed to set weight %u\n",
			    DEFAULT_WBFQ_WEIGHT);
			return (CEETM_FAILURE);
		}
	}
	cqinfo->cq = cq;
	ceetm_dbg("claimed cq %p, channel %p(%u), cqid %u\n",
	    cq, channel, channel->idx, classque);

	/* Claim a LFQ */
	ceetm_dbg("claiming lfq\n");
	if (qman_ceetm_lfq_claim(&lfq, cq)) {
		ceetm_err("failed to claim LFQ for cq %p(%u)\n",
		    cq, cq->idx);
		goto err_ret;
	}
	ceetm_dbg("claimed lfq %p idx %x for cq %p(%u)\n",
	    lfq, lfq->idx, cq, classque);
	cqinfo->lfq = lfq;

	context_a = (uint64_t)VQA_DPAA_VAL_TO_RELEASE_BUFFER;
	ceetm_dbg("set context\n");
	if (qman_ceetm_lfq_set_context(lfq, context_a, 0)) {
		ceetm_err("set context_a for lfq %p failed\n", lfq);
		goto err_ret;
	}

	/* create LFQ for egress */
	ceetm_dbg("creating fq\n");
	if (qman_ceetm_create_fq(lfq, &cqinfo->ceetmfq.egress_fq)) {
		ceetm_err("unable to create lfq %p\n", lfq);
		goto err_ret;
	}
	ceetm_dbg("created fq fqid %x(%u) for lfq %p, classque %u, "
	    "channel %u\n", cqinfo->ceetmfq.egress_fq.fqid,
	    cqinfo->ceetmfq.egress_fq.fqid, lfq, classque, channel->idx);
	return (CEETM_SUCCESS);

err_ret:
	if (cqinfo->lfq != NULL) {
		if (qman_ceetm_lfq_release(cqinfo->lfq) == 0)
			cqinfo->lfq = NULL;
	}
	if (cqinfo->cq != NULL) {
		if (qman_ceetm_cq_release(cqinfo->cq) == 0)
			cqinfo->cq = NULL;
	}
	return (CEETM_FAILURE);
}

/* ================================================================
 * ceetm_create_queues — create all 16 class queues on a channel
 * ================================================================ */

static int
ceetm_create_queues(struct ceetm_chnl_info *chnl_ctx)
{
	uint32_t ii;
	struct qm_ceetm_channel *channel;

	channel = chnl_ctx->channel;
	/* set WBFQ priority */
	chnl_ctx->wbfq_priority = CEETM_DEFA_WBFQ_PRIORITY;
	ii = GET_CEETM_PRIORITY(CEETM_DEFA_WBFQ_PRIORITY);
	ceetm_dbg("setting wbfq priority, ceetm_prio %u\n", ii);
	if (qman_ceetm_channel_set_group(channel, 0, ii, ii)) {
		ceetm_err("qman_ceetm_channel_set_group failed\n");
		return (CEETM_FAILURE);
	}

	/* set ceetm_cq ids in the cq structure */
	for (ii = 0; ii < NUM_CLASS_QUEUES; ii++)
		chnl_ctx->cq_info[ii].ceetm_idx = GET_CEETM_PRIORITY(ii);

	for (ii = 0; ii < NUM_CLASS_QUEUES; ii++) {
		/* create ccg for class queue */
		if (ceetm_create_ccg_for_class_queue(chnl_ctx, ii)) {
			ceetm_err("create_ccg_for_class_queue failed\n");
			return (CEETM_FAILURE);
		}
		/* set TD */
		if (ceetm_cfg_td_on_class_queue(chnl_ctx, ii,
		    DEFAULT_CQ_DEPTH)) {
			ceetm_err("cfg_td_on_class_queue failed\n");
			return (CEETM_FAILURE);
		}
		ceetm_dbg("ccg configured to class que\n");
		/* create class queues */
		if (ceetm_create_cq(chnl_ctx, ii)) {
			ceetm_err("create_cq failed on chnl %p\n", channel);
			return (CEETM_FAILURE);
		}
		ceetm_dbg("ceetm_create_cq done on chnl %p\n", channel);
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_create_channel_hw — create channel HW resources
 *
 * On FreeBSD, this is called from ceetm_assign_chnl() when the
 * channel is first assigned to a port (because channel_claim
 * requires an LNI).
 * ================================================================ */

static int
ceetm_create_channel_hw(struct ceetm_chnl_info *qm_channel,
    struct qm_ceetm_lni *lni)
{
	struct qm_ceetm_channel *channel;
	struct qm_ceetm_rate er_rate;

	if (qman_ceetm_channel_claim(&channel, lni)) {
		ceetm_err("unable to claim channel on ceetm\n");
		return (CEETM_FAILURE);
	}
	qm_channel->channel = channel;

	/* Enable Shaper by default, do not couple CR and ER */
	if (qman_ceetm_channel_enable_shaper(channel, 0)) {
		ceetm_err("unable to enable shaper for chnl %p\n", channel);
		return (CEETM_FAILURE);
	}

	er_rate.whole = CEETM_TOKEN_WHOLE_MAXVAL;
	er_rate.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	/* set max possible rate as default value */
	if (ceetm_program_channel_shaper(qm_channel,
	    &qm_channel->shaper_info.token_cr, &er_rate,
	    qm_channel->shaper_info.bsize)) {
		ceetm_err("unable to configure shaper for chnl %p\n",
		    channel);
		return (CEETM_FAILURE);
	}

	ceetm_dbg("created channel %u::%p\n", qm_channel->idx, channel);
	if (ceetm_create_queues(qm_channel)) {
		ceetm_err("unable to create queues on channel %p\n", channel);
		return (CEETM_FAILURE);
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_init_channels — initialise software state only
 *
 * On Linux, this creates all 8 channels with HW resources immediately.
 * On FreeBSD, HW channel creation is deferred to ceetm_assign_chnl()
 * because qman_ceetm_channel_claim() requires an LNI.  Here we only
 * set up the software defaults for shaper info, indices, and CQ info.
 * ================================================================ */

int
ceetm_init_channels(void)
{
	uint32_t ii, jj;
	struct ceetm_chnl_info *chinfo;
	struct classque_info *cqinfo;
	struct qm_ceetm_rate cr;
	uint64_t rate;

	memset(&qm_chnl_info, 0, sizeof(qm_chnl_info));
	memset(chnl_hw_created, 0, sizeof(chnl_hw_created));

	cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
	cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	if (qman_ceetm_tokenrate2bps(&cr, &rate, 0)) {
		ceetm_err("unable to deduce rate for shaper\n");
		return (CEETM_FAILURE);
	}

	chinfo = &qm_chnl_info[0];
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
		/* HW channel creation deferred to ceetm_assign_chnl() */
		chinfo++;
	}

	ceetm_dbg("channel software state initialised\n");
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_cfg_lni — configure LNI shaper from CMM command
 * ================================================================ */

int
ceetm_cfg_lni(struct tQM_context_ctl *qm_ctx, PQosShaperConfigCommand params)
{

	return (ceetm_cfg_shaper(qm_ctx, PORT_SHAPER_TYPE, params));
}

/* ================================================================
 * ceetm_cfg_channel — configure channel shaper
 * ================================================================ */

int
ceetm_cfg_channel(void *handle, uint32_t rate, uint32_t limit, uint32_t bsize)
{
	/* handle is channel number (as uint32_t cast to void*) */
	(void)handle;
	(void)rate;
	(void)limit;
	(void)bsize;
	/* Channel shaper configuration goes through ceetm_configure_shaper().
	 * This function exists only for interface compatibility. */
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_cfg_class_queue — placeholder (CQ creation done at assign)
 * ================================================================ */

int
ceetm_cfg_class_queue(struct tQM_context_ctl *qm_ctx, uint32_t classque)
{

	(void)qm_ctx;
	(void)classque;
	/* CQ creation is done during ceetm_assign_chnl() → create_queues() */
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_reset_qos — reset all CEETM state to defaults
 * ================================================================ */

int
ceetm_reset_qos(struct tQM_context_ctl *qm_ctx)
{
	uint32_t ii, jj;
	struct qm_ceetm_rate token;
	uint64_t rate;

	/* turn off port shaper — set limits very high */
	qm_ctx->shaper_info.token_cr.whole = CEETM_TOKEN_WHOLE_MAXVAL;
	qm_ctx->shaper_info.token_cr.fraction = CEETM_TOKEN_FRAC_MAXVAL;
	qm_ctx->shaper_info.bsize = CEETM_DEFA_BSIZE;
	qm_ctx->shaper_info.enable = 0;
	if (qman_ceetm_tokenrate2bps(&qm_ctx->shaper_info.token_cr,
	    &rate, 0)) {
		ceetm_err("qman_ceetm_tokenrate2bps failed\n");
		return (CEETM_FAILURE);
	}
	qm_ctx->shaper_info.rate = rate;
	token.whole = 0;
	token.fraction = 0;
	ceetm_dbg("turning port shaper off\n");
	if (ceetm_program_port_shaper(qm_ctx, &qm_ctx->shaper_info.token_cr,
	    &token, qm_ctx->shaper_info.bsize)) {
		ceetm_err("ceetm_program_port_shaper failed\n");
		return (CEETM_FAILURE);
	}

	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		struct ceetm_chnl_info *qm_channel;
		struct qm_ceetm_channel *channel;
		struct classque_info *cqinfo;
		uint32_t priority;

		/* program all mapped channels */
		if (!(qm_ctx->chnl_map & (1 << ii)))
			continue;
		if (!chnl_hw_created[ii])
			continue;

		qm_channel = &qm_chnl_info[ii];
		channel = qm_channel->channel;
		/* disable channel shaper */
		qm_channel->wbfq_priority = CEETM_DEFA_WBFQ_PRIORITY;
		qm_channel->wbfq_chshaper = 0;
		qm_channel->shaper_info.token_cr.whole =
		    CEETM_TOKEN_WHOLE_MAXVAL;
		qm_channel->shaper_info.token_cr.fraction =
		    CEETM_TOKEN_FRAC_MAXVAL;
		qm_channel->shaper_info.bsize = CEETM_DEFA_BSIZE;
		qm_channel->shaper_info.rate = rate;
		qm_channel->shaper_info.enable = 0;

		priority = GET_CEETM_PRIORITY(qm_channel->wbfq_priority);
		if (qman_ceetm_channel_set_group(channel, 0, priority,
		    priority)) {
			ceetm_err("qman_ceetm_channel_set_group failed\n");
			return (CEETM_FAILURE);
		}

		ceetm_dbg("turning channel %u shaper off\n", ii);
		if (ceetm_program_channel_shaper(qm_channel,
		    &qm_channel->shaper_info.token_cr,
		    &qm_channel->shaper_info.token_cr,
		    qm_channel->shaper_info.bsize)) {
			ceetm_err("ceetm_program_channel_shaper failed\n");
			return (CEETM_FAILURE);
		}

		/* program default weights, depths on all class queues */
		cqinfo = &qm_channel->cq_info[0];
		for (jj = 0; jj < MAX_SCHEDULER_QUEUES; jj++) {
			struct qm_ceetm_weight_code weight_code;

			if (!jj) {
				if (qman_ceetm_ratio2wbfs(DEFAULT_CQ_DEPTH, 1,
				    &weight_code, 0)) {
					ceetm_err("failed to convert weight\n");
					return (CEETM_FAILURE);
				}
			}
			cqinfo->qdepth = DEFAULT_CQ_DEPTH;
			if (ceetm_cfg_td_on_class_queue(qm_channel, jj,
			    cqinfo->qdepth)) {
				ceetm_err("cfg_td_on_class_queue failed "
				    "on chnl %u\n", ii);
				return (CEETM_FAILURE);
			}
			if (jj >= NUM_PQS) {
				/* wbfq — reset weight */
				cqinfo->weight = DEFAULT_WBFQ_WEIGHT;
				if (qman_ceetm_set_queue_weight(cqinfo->cq,
				    &weight_code)) {
					ceetm_err("set_queue_weight failed\n");
					return (CEETM_FAILURE);
				}
				if (qman_ceetm_channel_set_group_cr_eligibility(
				    channel, 0, 0)) {
					ceetm_err("set group cr elig failed\n");
					return (CEETM_FAILURE);
				}
				if (qman_ceetm_channel_set_group_er_eligibility(
				    channel, 0, 1)) {
					ceetm_err("set group er elig failed\n");
					return (CEETM_FAILURE);
				}
			} else {
				cqinfo->ch_shaper_enable = 0;
				/* priority queue — set CR/ER eligibility */
				if (qman_ceetm_channel_set_cq_cr_eligibility(
				    channel, jj, 0)) {
					ceetm_err("set cq cr elig failed\n");
					return (CEETM_FAILURE);
				}
				if (qman_ceetm_channel_set_cq_er_eligibility(
				    channel, jj, 1)) {
					ceetm_err("set cq er elig failed\n");
					return (CEETM_FAILURE);
				}
			}
			/* CQ policer profile reset — deferred */
			cqinfo->cq_shaper_enable = DISABLE_POLICER;
			cqinfo++;
		}
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_enable_or_disable_qos — enable/disable CEETM on a port
 * ================================================================ */

int
ceetm_enable_or_disable_qos(struct tQM_context_ctl *qm_ctx, uint32_t oper)
{
	struct qm_ceetm_rate token;
	struct ceetm_chnl_info *chnl_ctx;
	uint32_t ii;

	/* if context was not configured fully return error */
	if (!qm_ctx->chnl_map)
		return (QOS_ENERR_NOT_CONFIGURED);

	if (oper) {
		if (!qm_ctx->qos_enabled) {
			/* initialize lni */
			if (ceetm_setup_lni(qm_ctx)) {
				ceetm_err("ceetm_setup_lni failed\n");
				return (QOS_ENERR_IO);
			}

			token.whole = 0;
			token.fraction = 0;
			/* program lni, port shaper */
			if (ceetm_program_port_shaper(qm_ctx,
			    &qm_ctx->shaper_info.token_cr, &token,
			    qm_ctx->shaper_info.bsize)) {
				ceetm_err("program_port_shaper failed\n");
				return (QOS_ENERR_IO);
			}

			for (ii = 0; ii < NUM_CHANNEL_SHAPERS; ii++) {
				if (!(qm_ctx->chnl_map & (1 << ii)))
					continue;
				if (!chnl_hw_created[ii])
					continue;
				chnl_ctx = &qm_chnl_info[ii];
				/* configure channel shaper */
				if (!chnl_ctx->shaper_info.enable) {
					token.whole = CEETM_TOKEN_WHOLE_MAXVAL;
					token.fraction =
					    CEETM_TOKEN_FRAC_MAXVAL;
				}
				if (ceetm_program_channel_shaper(chnl_ctx,
				    &chnl_ctx->shaper_info.token_cr, &token,
				    chnl_ctx->shaper_info.bsize)) {
					ceetm_err("program_channel_shaper "
					    "failed\n");
					return (QOS_ENERR_IO);
				}
			}

			ceetm_dbg("calling qman_sp_enable_ceetm_mode "
			    "sp %p\n", qm_ctx->lni->sp);
			if (qman_sp_enable_ceetm_mode(
			    qm_ctx->lni->sp->dcp_idx,
			    qm_ctx->lni->sp->idx)) {
				ceetm_err("qman_sp_enable_ceetm_mode "
				    "failed\n");
				return (QOS_ENERR_IO);
			}

			/*
			 * On Linux: dpa_enable_ceetm(qm_ctx->net_dev)
			 * sets priv->ceetm_en = 1.  On FreeBSD,
			 * qm_ctx->qos_enabled is checked directly.
			 */
			qm_ctx->qos_enabled = 1;
			ceetm_dbg("CEETM enabled on iface %s\n",
			    qm_ctx->iface_info->name);
		} else {
			ceetm_dbg("already enabled\n");
		}
	} else {
		if (qm_ctx->qos_enabled) {
			/* disable port shaper */
			token.whole = CEETM_TOKEN_WHOLE_MAXVAL;
			token.fraction = CEETM_TOKEN_FRAC_MAXVAL;
			if (ceetm_program_port_shaper(qm_ctx, &token, &token,
			    CEETM_DEFA_BSIZE)) {
				ceetm_err("program_port_shaper failed\n");
				return (QOS_ENERR_IO);
			}
			/* disable channel shapers */
			for (ii = 0; ii < NUM_CHANNEL_SHAPERS; ii++) {
				if (!(qm_ctx->chnl_map & (1 << ii)))
					continue;
				if (!chnl_hw_created[ii])
					continue;
				chnl_ctx = &qm_chnl_info[ii];
				if (ceetm_program_channel_shaper(chnl_ctx,
				    &token, &token, CEETM_DEFA_BSIZE)) {
					ceetm_err("program_channel_shaper "
					    "failed\n");
					return (QOS_ENERR_IO);
				}
			}
			qm_ctx->qos_enabled = 0;
		} else {
			ceetm_dbg("already disabled\n");
		}
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_configure_shaper — port/channel shaper from CMM command
 * ================================================================ */

int
ceetm_configure_shaper(void *cmd)
{
	PQosShaperConfigCommand cfg;
	struct tQM_context_ctl *qm_ctx;

	cfg = (PQosShaperConfigCommand)cmd;
	if (cfg->cfg_flags & PORT_SHAPER_CFG) {
		struct cdx_port_info *port_info;

		/* port shaper */
		port_info = get_dpa_port_info((char *)cfg->ifname);
		if (port_info != NULL) {
			qm_ctx = QM_GET_CONTEXT(port_info->portid);
		} else {
			ceetm_err("unable to get context for port\n");
			return (CEETM_FAILURE);
		}
		if (ceetm_cfg_shaper(qm_ctx, PORT_SHAPER_TYPE, cfg)) {
			ceetm_err("ceetm_cfg_shaper failed for port\n");
			return (CEETM_FAILURE);
		}
	} else {
		struct ceetm_chnl_info *chnl_info;

		if (cfg->channel_num >= CDX_CEETM_MAX_CHANNELS) {
			ceetm_err("invalid channel number\n");
			return (CEETM_FAILURE);
		}
		chnl_info = &qm_chnl_info[cfg->channel_num];
		/* channel shaper */
		if (ceetm_cfg_shaper(chnl_info, CHANNEL_SHAPER_TYPE, cfg)) {
			ceetm_err("ceetm_cfg_shaper failed for channel\n");
			return (CEETM_FAILURE);
		}
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_configure_wbfq — configure WBFQ from CMM command
 * ================================================================ */

int
ceetm_configure_wbfq(void *cmd)
{
	struct ceetm_chnl_info *chnl_ctx;
	PQosWbfqConfigCommand cfg;
	struct qm_ceetm_channel *channel;
	uint32_t priority;

	cfg = (PQosWbfqConfigCommand)cmd;
	if (cfg->channel_num >= CDX_CEETM_MAX_CHANNELS) {
		ceetm_err("invalid channel number\n");
		return (CEETM_FAILURE);
	}
	chnl_ctx = &qm_chnl_info[cfg->channel_num];
	channel = chnl_ctx->channel;
	if (channel == NULL) {
		ceetm_err("channel %u not yet HW-initialised\n",
		    cfg->channel_num);
		return (CEETM_FAILURE);
	}
	priority = GET_CEETM_PRIORITY(cfg->priority);
	ceetm_dbg("channel %u cfg prio %u, ceetm prio %u\n",
	    cfg->channel_num, cfg->priority, priority);

	if (cfg->cfg_flags & WBFQ_PRIORITY_VALID) {
		if (qman_ceetm_channel_set_group(channel, 0, priority,
		    priority)) {
			ceetm_err("qman_ceetm_channel_set_group failed\n");
			return (CEETM_FAILURE);
		}
		chnl_ctx->wbfq_priority = cfg->priority;
	}

	/* set shaper eligibility */
	ceetm_dbg("setting shaper on wbfq queues\n");
	if (cfg->cfg_flags & WBFQ_SHAPER_VALID) {
		if (qman_ceetm_channel_set_group_cr_eligibility(channel, 0,
		    cfg->wbfq_chshaper)) {
			ceetm_err("set group cr eligibility failed\n");
			return (CEETM_FAILURE);
		}
		if (qman_ceetm_channel_set_group_er_eligibility(channel, 0,
		    (cfg->wbfq_chshaper ^ 1))) {
			ceetm_err("set group er eligibility failed\n");
			return (CEETM_FAILURE);
		}
	}
	chnl_ctx->wbfq_chshaper = cfg->wbfq_chshaper;
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_configure_cq — configure CQ from CMM command
 * ================================================================ */

int
ceetm_configure_cq(void *cmd)
{
	PQosCqConfigCommand cfg;
	uint32_t ceetm_quenum;
	struct ceetm_chnl_info *chnl_ctx;

	cfg = (PQosCqConfigCommand)cmd;
	if (cfg->channel_num >= CDX_CEETM_MAX_CHANNELS) {
		ceetm_err("invalid channel number %u\n", cfg->channel_num);
		return (CEETM_FAILURE);
	}
	if (cfg->quenum >= NUM_CLASS_QUEUES) {
		ceetm_err("invalid queue number %u\n", cfg->quenum);
		return (CEETM_FAILURE);
	}

	chnl_ctx = &qm_chnl_info[cfg->channel_num];

	/* CQ policer rate — deferred */
	if (cfg->cfg_flags & CQ_RATE_VALID) {
		ceetm_dbg("CQ policer rate config deferred\n");
		return (CEETM_SUCCESS);
	}

	/* adjust quenum for strict priority types */
	ceetm_quenum = chnl_ctx->cq_info[cfg->quenum].ceetm_idx;
	ceetm_dbg("channel %u, cfg que %u, ceetm que %u\n",
	    cfg->channel_num, cfg->quenum, ceetm_quenum);

	/* qdepth applicable to both queue types */
	if (cfg->cfg_flags & CQ_TDINFO_VALID) {
		if (ceetm_cfg_td_on_class_queue(chnl_ctx, ceetm_quenum,
		    cfg->tdthresh))
			return (CEETM_FAILURE);
		chnl_ctx->cq_info[cfg->quenum].qdepth = cfg->tdthresh;
	}

	if (cfg->cfg_flags & CQ_WEIGHT_VALID) {
		struct qm_ceetm_weight_code weight_code;

		/* weight applicable to WBFQ only */
		if (ceetm_quenum < CEETM_WBFS_START)
			return (CEETM_FAILURE);
		if (qman_ceetm_ratio2wbfs(cfg->weight, 1, &weight_code, 0)) {
			ceetm_err("invalid value %u for que weight\n",
			    cfg->weight);
			return (CEETM_FAILURE);
		}
		if (qman_ceetm_set_queue_weight(
		    chnl_ctx->cq_info[cfg->quenum].cq, &weight_code)) {
			ceetm_err("qman_ceetm_set_queue_weight failed\n");
			return (CEETM_FAILURE);
		}
		chnl_ctx->cq_info[cfg->quenum].weight = cfg->weight;
	}

	if (cfg->cfg_flags & CQ_SHAPER_CFG_VALID) {
		uint32_t enable;
		struct qm_ceetm_channel *channel;

		channel = chnl_ctx->channel;
		enable = cfg->ch_shaper_en ? 1 : 0;
		if (ceetm_quenum < CEETM_WBFS_START) {
			ceetm_dbg("setting shaper on prio queues\n");
			if (qman_ceetm_channel_set_cq_cr_eligibility(channel,
			    ceetm_quenum, enable)) {
				ceetm_err("set cq cr eligibility failed\n");
				return (CEETM_FAILURE);
			}
			if (qman_ceetm_channel_set_cq_er_eligibility(channel,
			    ceetm_quenum, (enable ^ 1))) {
				ceetm_err("set cq er eligibility failed\n");
				return (CEETM_FAILURE);
			}
		}
		chnl_ctx->cq_info[cfg->quenum].ch_shaper_enable = enable;
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_assign_chnl — assign channel to interface
 *
 * On FreeBSD, this also creates HW channel resources if not done yet.
 * ================================================================ */

int
ceetm_assign_chnl(struct tQM_context_ctl *qm_ctx, uint32_t channel_num)
{
	uint32_t ii;
	struct ceetm_chnl_info *chnl_ctx;

	if (channel_num >= CDX_CEETM_MAX_CHANNELS) {
		ceetm_err("invalid channel number %u\n", channel_num);
		return (CEETM_FAILURE);
	}
	chnl_ctx = &qm_chnl_info[channel_num];
	if (chnl_ctx->qm_ctx != NULL) {
		ceetm_err("channel %u already assigned to iface %s\n",
		    channel_num, qm_ctx->iface_info->name);
		return (CEETM_FAILURE);
	}
	if (qm_ctx->lni == NULL) {
		ceetm_err("no LNI on iface %s (call ceetm_create_lni first)\n",
		    qm_ctx->iface_info->name);
		return (CEETM_FAILURE);
	}

	ceetm_dbg("assigning channel %u(%u) to iface %s\n",
	    channel_num, chnl_ctx->idx, qm_ctx->iface_info->name);

	/*
	 * FreeBSD: Create HW channel resources if not yet done.
	 * qman_ceetm_channel_claim() allocates the HW channel index
	 * and sends the MAPPING_SHAPER_TCFC command to map it to the LNI.
	 */
	if (!chnl_hw_created[channel_num]) {
		if (ceetm_create_channel_hw(chnl_ctx, qm_ctx->lni)) {
			ceetm_err("failed to create HW channel %u\n",
			    channel_num);
			return (CEETM_FAILURE);
		}
		chnl_hw_created[channel_num] = 1;
	}

	chnl_ctx->qm_ctx = qm_ctx;
	qm_ctx->chnl_map |= (1 << chnl_ctx->idx);
	ceetm_dbg("lni %u, dcp %u, chnl_map %x\n",
	    qm_ctx->lni->idx, qm_ctx->lni->dcp_idx, qm_ctx->chnl_map);

	/* set net_dev on all class queue FQs */
	for (ii = 0; ii < NUM_CLASS_QUEUES; ii++)
		chnl_ctx->cq_info[ii].ceetmfq.net_dev = qm_ctx->net_dev;

	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_get_qos_cfg — query current QoS configuration
 * ================================================================ */

int
ceetm_get_qos_cfg(struct tQM_context_ctl *ctx, pQosQueryCmd query)
{
	uint32_t ii;
	struct shaper_info *shaper_info;
	struct ceetm_chnl_info *chnl_info;

	query->if_qos_enabled = ctx->qos_enabled;
	shaper_info = &ctx->shaper_info;
	query->shaper_enabled = shaper_info->enable;
	if (query->shaper_enabled) {
		query->rate = (shaper_info->rate / 1000);
		query->bsize = shaper_info->bsize;
		ceetm_dbg("port shaper enabled:: rate %u, bsize %u\n",
		    query->rate, query->bsize);
	}

	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		if (ctx->chnl_map & (1 << ii)) {
			chnl_info = &qm_chnl_info[ii];
			query->chnl_shaper_info[ii].valid = 1;
			query->chnl_shaper_info[ii].shaper_enabled =
			    chnl_info->shaper_info.enable;
			if (chnl_info->shaper_info.enable) {
				query->chnl_shaper_info[ii].rate =
				    (chnl_info->shaper_info.rate / 1000);
				query->chnl_shaper_info[ii].bsize =
				    chnl_info->shaper_info.bsize;
			}
		} else {
			query->chnl_shaper_info[ii].valid = 0;
		}
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * ceetm_get_cq_query — query CQ statistics from hardware
 * ================================================================ */

static int
ceetm_get_fqcount(struct ceetm_chnl_info *chnl_ctx, uint32_t classque,
    uint32_t *fqcount)
{
	struct qm_mcr_ceetm_cq_query query;
	struct qm_ceetm_cq *cq;
	struct tQM_context_ctl *qm_ctx;

	qm_ctx = chnl_ctx->qm_ctx;
	if (qm_ctx == NULL) {
		ceetm_err("invalid channel context\n");
		return (CEETM_FAILURE);
	}
	cq = (struct qm_ceetm_cq *)chnl_ctx->cq_info[classque].cq;
	memset(&query, 0, sizeof(query));
	if (qman_ceetm_query_cq(cq->idx, qm_ctx->port_info->fm_index,
	    &query)) {
		ceetm_err("error getting ceetm cq fields\n");
		return (CEETM_FAILURE);
	}
	*fqcount = (((uint32_t)query.frm_cnt_hi << 16) |
	    be16toh(query.frm_cnt_lo));
	return (CEETM_SUCCESS);
}

int
ceetm_get_cq_query(pQosCqQueryCmd cmd)
{
	uint32_t quenum;
	uint64_t pkt_count;
	uint64_t byte_count;
	struct qm_ceetm_cq *cq;
	struct qm_ceetm_ccg *ccg;
	struct ceetm_chnl_info *chnl_ctx;
	struct classque_info *cq_info;

	if (cmd->channel_num >= CDX_CEETM_MAX_CHANNELS) {
		ceetm_err("invalid channel number %u\n", cmd->channel_num);
		return (CEETM_FAILURE);
	}
	quenum = cmd->queuenum;
	if (quenum >= CDX_CEETM_MAX_QUEUES_PER_CHANNEL) {
		ceetm_err("invalid queue number %u\n", quenum);
		return (CEETM_FAILURE);
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
		ceetm_err("failed to get fq count on que %u\n", quenum);
		return (CEETM_FAILURE);
	}

	if (qman_ceetm_cq_get_dequeue_statistics(cq, cmd->clear_stats,
	    &pkt_count, &byte_count)) {
		ceetm_err("failed to get cq deque stats %u\n", quenum);
		return (CEETM_FAILURE);
	}
	cmd->deque_pkts_high = (pkt_count >> 32);
	cmd->deque_pkts_lo = (pkt_count & 0xffffffff);
	cmd->deque_bytes_high = (byte_count >> 32);
	cmd->deque_bytes_lo = (byte_count & 0xffffffff);

	if (qman_ceetm_ccg_get_reject_statistics(ccg, cmd->clear_stats,
	    &pkt_count, &byte_count)) {
		ceetm_err("failed to get cq reject stats %u\n", quenum);
		return (CEETM_FAILURE);
	}
	cmd->reject_pkts_high = (pkt_count >> 32);
	cmd->reject_pkts_lo = (pkt_count & 0xffffffff);
	cmd->reject_bytes_high = (byte_count >> 32);
	cmd->reject_bytes_lo = (byte_count & 0xffffffff);

	cmd->cq_shaper_on = cq_info->cq_shaper_enable;
	cmd->cir = cq_info->shaper_rate;

	/* CQ policer counter query — deferred */

	return (CEETM_SUCCESS);
}

/* ================================================================
 * DSCP → FQ mapping
 * ================================================================ */

int
ceetm_enable_disable_dscp_fq_map(struct tQM_context_ctl *qm_ctx,
    uint8_t status)
{

	if (status && qm_ctx->dscp_fq_map != NULL) {
		ceetm_err("dscp_fq_map is already enabled\n");
		return (CEETM_SUCCESS);
	}
	if (!status && qm_ctx->dscp_fq_map == NULL) {
		ceetm_err("dscp_fq_map is already disabled\n");
		return (CEETM_SUCCESS);
	}
	if (status) {
		if (enable_dscp_fqid_map(qm_ctx->port_info->portid)) {
			ceetm_err("failed to enable dscp fqid mapping "
			    "for port %s\n", qm_ctx->iface_info->name);
			return (CEETM_FAILURE);
		}
		if (qm_ctx->dscp_fq_map != NULL) {
			ceetm_err("earlier dscp disable not proper\n");
			return (CEETM_FAILURE);
		}
		qm_ctx->dscp_fq_map = kzalloc(
		    sizeof(struct qm_dscp_fq_map), GFP_KERNEL);
		if (qm_ctx->dscp_fq_map == NULL) {
			ceetm_err("failed to create dscp fq map for %s\n",
			    qm_ctx->iface_info->name);
			disable_dscp_fqid_map(qm_ctx->port_info->portid);
			return (CEETM_FAILURE);
		}
	} else {
		if (disable_dscp_fqid_map(qm_ctx->port_info->portid)) {
			ceetm_err("failed to disable dscp fqid mapping "
			    "for port %s\n", qm_ctx->iface_info->name);
			return (CEETM_FAILURE);
		}
		kfree(qm_ctx->dscp_fq_map);
		qm_ctx->dscp_fq_map = NULL;
	}
	return (CEETM_SUCCESS);
}

static int
dscp_fq_unmap(struct tQM_context_ctl *qm_ctx, uint8_t dscp)
{

	if (qm_ctx->dscp_fq_map == NULL) {
		ceetm_err("dscp to fq map is not enabled on %s\n",
		    qm_ctx->iface_info->name);
		return (CEETM_FAILURE);
	}
	qm_ctx->dscp_fq_map->dscp_fq[dscp] = NULL;
	return (CEETM_SUCCESS);
}

int
reset_all_dscp_fq_map_ff(cdx_dscp_fqid_t *muram_dscp_fqid_map)
{
	int index;

	for (index = 0; index < MAX_DSCP; index++)
		muram_dscp_fqid_map->fqid[index] = 0;
	return (CEETM_SUCCESS);
}

int
reset_dscp_fq_map_ff(cdx_dscp_fqid_t *muram_dscp_fqid_map, uint8_t dscp)
{

	muram_dscp_fqid_map->fqid[dscp] = 0;
	return (CEETM_SUCCESS);
}

static int
dscp_fq_unmap_ff(struct tQM_context_ctl *qm_ctx, uint8_t dscp)
{
	cdx_dscp_fqid_t *dscp_fqid_map;

	dscp_fqid_map = get_dscp_fqid_map(qm_ctx->port_info->portid);
	if (dscp_fqid_map == NULL)
		return (CEETM_FAILURE);
	if (reset_dscp_fq_map_ff(dscp_fqid_map, dscp))
		return (CEETM_FAILURE);
	return (CEETM_SUCCESS);
}

int
ceetm_dscp_fq_unmap(struct tQM_context_ctl *qm_ctx, uint8_t dscp)
{

	if (dscp_fq_unmap(qm_ctx, dscp)) {
		ceetm_err("dscp to fq unmap failed on %s\n",
		    qm_ctx->iface_info->name);
		return (CEETM_FAILURE);
	}
	if (dscp_fq_unmap_ff(qm_ctx, dscp)) {
		ceetm_err("dscp to fq unmap ff failed on %s\n",
		    qm_ctx->iface_info->name);
		return (CEETM_FAILURE);
	}
	return (CEETM_SUCCESS);
}

static int
add_dscp_fq_map(struct tQM_context_ctl *qm_ctx, uint8_t dscp,
    struct qman_fq *egress_fq)
{

	if (qm_ctx->dscp_fq_map == NULL) {
		ceetm_err("dscp to fq map is not enabled on %s\n",
		    qm_ctx->iface_info->name);
		return (CEETM_FAILURE);
	}
	qm_ctx->dscp_fq_map->dscp_fq[dscp] = egress_fq;
	return (CEETM_SUCCESS);
}

static int
add_dscp_fq_map_ff(struct tQM_context_ctl *qm_ctx, uint8_t dscp,
    struct qman_fq *egress_fq)
{
	cdx_dscp_fqid_t *dscp_fqid_map;

	dscp_fqid_map = get_dscp_fqid_map(qm_ctx->port_info->portid);
	if (dscp_fqid_map == NULL)
		return (CEETM_FAILURE);
	dscp_fqid_map->fqid[dscp] = htobe32(egress_fq->fqid);
	return (CEETM_SUCCESS);
}

int
ceetm_dscp_fq_map(struct tQM_context_ctl *qm_ctx, uint8_t dscp,
    uint8_t channel_num, uint8_t clsqueue_num)
{
	struct qman_fq *egress_fq;

	/* slow path get egress fq */
	egress_fq = ceetm_get_egressfq(qm_ctx, channel_num, clsqueue_num, 0);
	if (egress_fq == NULL) {
		ceetm_err("failed to find egress fq for channel %u cq %u "
		    "on %s\n", channel_num, clsqueue_num,
		    qm_ctx->iface_info->name);
		return (CEETM_FAILURE);
	}
	if (add_dscp_fq_map(qm_ctx, dscp, egress_fq)) {
		ceetm_err("failed to add dscp %u fq %u map on %s\n",
		    dscp, egress_fq->fqid, qm_ctx->iface_info->name);
		return (CEETM_FAILURE);
	}

	/* fast path get egress fq */
	egress_fq = ceetm_get_egressfq(qm_ctx, channel_num, clsqueue_num, 1);
	if (egress_fq == NULL) {
		ceetm_err("failed to find egress fq for channel %u cq %u "
		    "on %s\n", channel_num, clsqueue_num,
		    qm_ctx->iface_info->name);
		dscp_fq_unmap(qm_ctx, dscp);
		return (CEETM_FAILURE);
	}
	if (add_dscp_fq_map_ff(qm_ctx, dscp, egress_fq)) {
		ceetm_err("failed to add dscp %u fq %u map on %s\n",
		    dscp, egress_fq->fqid, qm_ctx->iface_info->name);
		dscp_fq_unmap(qm_ctx, dscp);
		return (CEETM_FAILURE);
	}
	return (CEETM_SUCCESS);
}

int
ceetm_get_dscp_fq_map(struct tQM_context_ctl *qm_ctx,
    PQosIfaceDscpFqidMapCommand cmd)
{
	cdx_dscp_fqid_t *dscp_fqid_map;
	uint16_t index;

	dscp_fqid_map = get_dscp_fqid_map(qm_ctx->port_info->portid);
	if (dscp_fqid_map != NULL) {
		for (index = 0; index < MAX_DSCP; index++)
			cmd->fqid[index] = be32toh(dscp_fqid_map->fqid[index]);
	} else {
		ceetm_err("DSCP to fqmap is not enabled on %s\n",
		    qm_ctx->iface_info->name);
		memset(cmd->fqid, 0, sizeof(uint32_t) * MAX_DSCP);
	}
	return (CEETM_SUCCESS);
}

/* ================================================================
 * RegisterCEETMHandler — not needed on FreeBSD
 *
 * On Linux, this registers ceetm_get_egressfq/ceetm_get_dscp_fq
 * as callback function pointers in the DPAA ethernet driver.
 * On FreeBSD, cdx_get_txfq() in cdx_devman_freebsd.c calls
 * ceetm_get_egressfq() directly.
 * ================================================================ */

void
RegisterCEETMHandler(FnHandler pCeetmGetQueue)
{

	(void)pCeetmGetQueue;
}

/* ================================================================
 * ceetm_exit — cleanup
 * ================================================================ */

int
ceetm_exit(void)
{

	/*
	 * TODO: Full cleanup — release channels, CQs, LFQs, CCGs.
	 * For now, the kernel CEETM resources persist until kldunload/reboot.
	 */
	ceetm_dbg("ceetm_exit\n");
	return (CEETM_SUCCESS);
}
