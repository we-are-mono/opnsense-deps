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

#include "cdx.h"
#include "cdx_ioctl.h"
#include "portdefs.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "misc.h"

QM_context_ctl gQMCtx[MAX_PHY_PORTS];


//uncomment to disable Egress QOS 
//#define DISABLE_EGRESS_QOS	1

/** QOS command executer.
 * This function is the QOS handler function / the entry point
 * to process the qos commands
 *
 * @param cmd_code   Command code.
 * @param cmd_len    Command length.
 * @param p          Command structure.
 *
 */

static U16 M_qm_cmdproc(U16 cmd_code, U16 cmd_len, U16 *p)
{
#ifdef ENABLE_EGRESS_QOS	
	struct tQM_context_ctl *qm_ctx;
	struct cdx_port_info *port_info;
#endif
	U16 rtncode = 0;
	U16 retlen = 2;

	rtncode = CMD_OK;
#ifdef QM_DEBUG
	printk(KERN_INFO "%s: cmd_code=0x%x\n", __func__, cmd_code);
#endif
	switch (cmd_code)
	{
#ifdef ENABLE_EGRESS_QOS	
		case CMD_QM_RESET:
			{
				PQosResetCommand pcmd;

				pcmd = (PQosResetCommand)p;
				port_info = get_dpa_port_info(pcmd->ifname);
				if (port_info)
				{
					qm_ctx = QM_GET_CONTEXT(port_info->portid);
					if (ceetm_reset_qos(qm_ctx))
						rtncode = CMD_ERR;
				} else 
					rtncode = CMD_ERR;

				break;		
			}
		case CMD_QM_QOSENABLE:
			{
				PQosEnableCommand pcmd;

				pcmd = (PQosEnableCommand)p;
				port_info = get_dpa_port_info(pcmd->ifname);
				if (port_info)
				{
					qm_ctx = QM_GET_CONTEXT(port_info->portid);
					rtncode = ceetm_enable_or_disable_qos(qm_ctx, pcmd->enable_flag);
				} else 
					rtncode = QOS_ENERR_INVAL_PARAM;

				break;		
			}

		case CMD_QM_SHAPER_CONFIG:
			{
				PQosShaperConfigCommand pcmd = (PQosShaperConfigCommand)p;

				if (ceetm_configure_shaper(pcmd))
					rtncode = CMD_ERR;
				break;
			}

		case CMD_QM_WBFQ_CONFIG:
			{
				PQosWbfqConfigCommand pcmd = (PQosWbfqConfigCommand)p;
				if (ceetm_configure_wbfq(pcmd))
					rtncode = CMD_ERR;
				break;
			}

		case CMD_QM_CQ_CONFIG:
			{
				PQosCqConfigCommand pcmd = (PQosCqConfigCommand)p;

				if (ceetm_configure_cq(pcmd))
					rtncode = CMD_ERR;
				break;
			}
		case CMD_QM_CHNL_ASSIGN:
			{		
				PQosChnlAssignCommand pcmd = (PQosChnlAssignCommand)p;

				port_info = get_dpa_port_info(pcmd->ifname);
				if (port_info)
				{
					qm_ctx = QM_GET_CONTEXT(port_info->portid);
					if (ceetm_assign_chnl(qm_ctx, pcmd->channel_num))
						rtncode = CMD_ERR;
				} else
					rtncode = CMD_ERR;
				break;
			}	
		case CMD_QM_DSCP_Q_MAP_STATUS:
		case CMD_QM_DSCP_Q_MAP_CFG:
		case CMD_QM_DSCP_Q_MAP_RESET:
			{		
				PQosDscpChnlClsq_mapCmd pcmd;

				pcmd = (PQosDscpChnlClsq_mapCmd)p;
				port_info = get_dpa_port_info(pcmd->ifname);
				if (port_info)
				{
					qm_ctx = QM_GET_CONTEXT(port_info->portid);
					if (!qm_ctx->qos_enabled)
					{
						DPA_ERROR("%s()::%d QoS not enabled on this interface <%s>\n", __FUNCTION__, __LINE__, qm_ctx->iface_info->name);
						rtncode = QOS_ENERR_NOT_CONFIGURED;
					}
					else
					{
						if (cmd_code == CMD_QM_DSCP_Q_MAP_STATUS)
						{
							if (ceetm_enable_disable_dscp_fq_map(qm_ctx, 
												pcmd->status))
							{
								rtncode = CMD_ERR;
								DPA_ERROR("%s()::%d return error %d QOS_ENERR_INVAL_PARAM\n", __FUNCTION__, __LINE__, rtncode);
							}
						}
						else if (cmd_code == CMD_QM_DSCP_Q_MAP_CFG)
						{
							if (ceetm_dscp_fq_map(qm_ctx, pcmd->dscp, pcmd->channel_num,
										pcmd->clsqueue_num))
							{
								rtncode = CMD_ERR;
								DPA_ERROR("%s()::%d return error %d QOS_ENERR_INVAL_PARAM\n", __FUNCTION__, __LINE__, rtncode);
							}
						}
						else /* cmd_code will be CMD_QM_DSCP_Q_MAP_RESET */
						{
							if (ceetm_dscp_fq_unmap(qm_ctx, pcmd->dscp))
							{
								rtncode = CMD_ERR;
								DPA_ERROR("%s()::%d return error %d QOS_ENERR_INVAL_PARAM\n", __FUNCTION__, __LINE__, rtncode);
							}
						}
					}
				} else 
				{
					rtncode = QOS_ENERR_INVAL_PARAM;
					DPA_ERROR("%s()::%d return error %d QOS_ENERR_INVAL_PARAM\n", __FUNCTION__, __LINE__, rtncode);
				}
				break;
			}	
#endif
		case CMD_QM_EXPT_RATE:
			{
				PQosExptRateCommand pexptrate;

				pexptrate = (PQosExptRateCommand)p;
#ifdef QM_DEBUG
				printk("%s::interface %d, rate pkts/s %d burst_size :%d\n",  __FUNCTION__,
						pexptrate->expt_iftype,
						pexptrate->pkts_per_sec,  pexptrate->burst_size);
#endif
				//using fman index as 0 as there is only one fman
				if (cdx_set_expt_rate(FMAN_INDEX, pexptrate->expt_iftype, pexptrate->pkts_per_sec, pexptrate->burst_size)) {
					rtncode = CMD_ERR;
				} 
				break;
			}

		case CMD_QM_FF_RATE:
			{
				PQosFFRateCommand prate;

				prate = (PQosFFRateCommand)p;
				if (cdx_set_ff_rate(prate->interface,  prate->cir, prate->pir)) {
					rtncode = CMD_ERR;
				}
				break;
			}

#ifdef ENABLE_EGRESS_QOS	
		case CMD_QM_QUERY:
			{
				pQosQueryCmd pcmd = (pQosQueryCmd)p;

				if (!(port_info = get_dpa_port_info(pcmd->interface)))
				{
					rtncode = CMD_ERR;
					break;
				}
				qm_ctx = QM_GET_CONTEXT(port_info->portid);
				if (ceetm_get_qos_cfg(qm_ctx, pcmd)) {
					rtncode = CMD_ERR;
				} else {
					retlen = sizeof(QosQueryCmd);
				}
				break;
			}
		case CMD_QM_QUERY_QUEUE:
			{
				pQosCqQueryCmd cqcmd;

				cqcmd = (pQosCqQueryCmd)p;
				if (ceetm_get_cq_query(cqcmd)) {
					rtncode = CMD_ERR;
				} else {
					retlen = sizeof(QosCqQueryCmd);
				}
				break;
			}
#endif		
		case CMD_QM_QUERY_FF_RATE:
			{
				PQosFFRateCommand prate;

				prate = (PQosFFRateCommand)p;
				if (cdx_get_ff_rate(prate)) { 
					rtncode = CMD_ERR;
				} else {
					retlen = sizeof(QosFFRateCommand);
#ifdef QM_DEBUG
					printk("%s::port %s cir rate pkts/s %d, pir rate %d\n",  __FUNCTION__,
							prate->interface, prate->cir, prate->pir);
#endif
				}
				break;
			}

		case CMD_QM_QUERY_EXPT_RATE:
			{
				PQosExptRateCommand pexptrate;

				pexptrate = (PQosExptRateCommand)p;
				if (cdx_get_expt_rate(pexptrate)) {
					rtncode = CMD_ERR;
				} else {
					retlen = sizeof(QosExptRateCommand);
				}
				break;
			}
#ifdef ENABLE_INGRESS_QOS
		case CMD_QM_QUERY_IFACE_DSCP_FQID_MAP:
			{
				PQosIfaceDscpFqidMapCommand pDscpFqMap;

				pDscpFqMap = (PQosIfaceDscpFqidMapCommand)p;
				port_info = get_dpa_port_info(pDscpFqMap->ifname);
				if (port_info)
				{
					qm_ctx = QM_GET_CONTEXT(port_info->portid);
					if (!qm_ctx->qos_enabled)
					{
						DPA_ERROR("%s()::%d QoS not enabled on this interface <%s>\n", __FUNCTION__, __LINE__, qm_ctx->iface_info->name);
						rtncode = QOS_ENERR_NOT_CONFIGURED;
					}
					else
					{
						if (!qm_ctx->dscp_fq_map)
							pDscpFqMap->enable = 0;
						else
							pDscpFqMap->enable = 1;

						if (ceetm_get_dscp_fq_map(qm_ctx, pDscpFqMap)) {
							rtncode = CMD_ERR;
						} else {
							retlen = sizeof(QosIfaceDscpFqidMapCommand);
							DPA_INFO("retlen %d \n", retlen);
						}
					}
				}
				else
					rtncode = CMD_ERR;
				break;
			}
		case CMD_QM_INGRESS_POLICER_ENABLE:
			{
				PIngressQosEnableCommand pcmd;

				pcmd = (PIngressQosEnableCommand)p;

				/* using fman index as 0 as there is only one fman */
				rtncode = cdx_ingress_enable_or_disable_qos(FMAN_INDEX,pcmd->queue_no,pcmd->enable_flag);

				break;
			}
		case CMD_QM_INGRESS_POLICER_CONFIG:
			{
				PIngressQosCfgCommand pcmd;

				pcmd = (PIngressQosCfgCommand)p;

				/* using fman index as 0 as there is only one fman */
				rtncode = cdx_ingress_policer_modify_config(FMAN_INDEX,pcmd->queue_no,pcmd->cir,pcmd->pir,
						                                  DEFAULT_INGRESS_BYTE_MODE_CBS, DEFAULT_INGRESS_BYTE_MODE_PBS );

				break;
			}
		case CMD_QM_INGRESS_POLICER_RESET:
			{
				/* using fman index as 0 as there is only one fman */
				if (cdx_ingress_policer_reset(FMAN_INDEX))
					rtncode = CMD_ERR;
				break;
			}
		case CMD_QM_INGRESS_POLICER_QUERY_STATS:
			{
				pIngressQosStatCmd pcmd;
				pIngressQosStat pstats;
				uint32_t ii;

				pcmd = (pIngressQosStatCmd)p;
				for(ii = 0; ii< INGRESS_FLOW_POLICER_QUEUES; ii++ ) {
					pstats = &pcmd->policer_stats[ii];

					/* using fman index as 0 as there is only one fman */
					cdx_ingress_policer_stats(FMAN_INDEX,ii,pstats,pcmd->clear);
				}
				retlen = (sizeof(IngressQosStat) * INGRESS_FLOW_POLICER_QUEUES );
				break;
			}
#ifdef SEC_PROFILE_SUPPORT
		case CMD_QM_SEC_POLICER_CONFIG:
			{
				PQosSecRateCommand pcmd;

				pcmd = (PQosSecRateCommand)p;

				/* using fman index as 0 as there is only one fman */
				rtncode = cdx_ingress_policer_modify_config(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM, pcmd->cir, pcmd->pir, pcmd->cbs, pcmd->pbs);

				break;
			}
		case CMD_QM_SEC_POLICER_QUERY_STATS:
			{
				pSecQosStatCmd pcmd;
				pIngressQosStat pstats;

				pcmd = (pSecQosStatCmd)p;
				pstats = &pcmd->policer_stats;

				/* using fman index as 0 as there is only one fman */
				cdx_ingress_policer_stats(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
						pstats, pcmd->clear);
				retlen = sizeof(IngressQosStat);
				break;
			}
		case CMD_QM_SEC_POLICER_RESET:
			{
				/* using fman index as 0 as there is only one fman */
				if (cdx_sec_policer_reset(FMAN_INDEX))
					rtncode = CMD_ERR;
				break;
			}
#endif /* endif for SEC_PROFILE_SUPPORT */
#endif
			// unknown command code
		default:
			{
				/* printk("%s::unknown command %x\n", __FUNCTION__, cmd_code); */
				rtncode = CMD_ERR;
				break;
			}
	}

	*p = rtncode;
#ifdef QM_DEBUG
	if (rtncode != 0)
		printk(KERN_INFO "%s: Command error, rtncode=%d", __func__, (short)rtncode);
#endif
	return retlen;
}

/** QOS init function.
 * This function initializes the qos control context with default configuration
 * and sends the same configuration to TMU.
 *
 */
int qm_init(void)
{
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	set_cmd_handler(EVENT_QM,M_qm_cmdproc);
#ifdef ENABLE_EGRESS_QOS	
	memset(&gQMCtx[0], 0, (sizeof(QM_context_ctl) * GEM_PORTS));
	ceetm_init_channels();
#endif
	return NO_ERR;
}
/** QOS exit function.
 */
void qm_exit(void)
{
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
#ifdef ENABLE_EGRESS_QOS	
	ceetm_exit();
#endif
	return;
}

#if MAX_SCHEDULER_QUEUES > DPAA_ETH_TX_QUEUES
#error MAX_SCHEDULER_QUEUES exceeds DPAA_ETH_TX_QUEUES
#endif

int cdx_enable_ceetm_on_iface(struct dpa_iface_info *iface_info) 
{
#ifdef ENABLE_EGRESS_QOS	
	struct cdx_port_info *port_info;
	struct tQM_context_ctl *qm_ctx;

	if (!(port_info = get_dpa_port_info(iface_info->name)))
	{
		ceetm_err("%s::unable to get port info for port %s\n",
				__FUNCTION__, iface_info->name);		
		return FAILURE;
	}
	qm_ctx = QM_GET_CONTEXT(port_info->portid);
	if (qm_ctx->qos_enabled) {
		ceetm_err("%s::qos already enabled for port %s\n",
				__FUNCTION__, iface_info->name);		
		return FAILURE;
	}

	qm_ctx->dscp_fq_map = NULL;

	qm_ctx->iface_info = iface_info;
	qm_ctx->port_info = port_info;
	qm_ctx->qos_enabled = 0;
	qm_ctx->net_dev = iface_info->eth_info.net_dev;
	if (!qm_ctx->net_dev) {
		return FAILURE;
	}
	/* create lni */	
	if (ceetm_create_lni(qm_ctx))
		return FAILURE;
	/* Add qm_ctx to priv structure */
	{
		struct dpa_priv_s *priv;

		priv = netdev_priv(qm_ctx->net_dev);
		priv->qm_ctx = qm_ctx;
	}
#endif
	return SUCCESS;
}
