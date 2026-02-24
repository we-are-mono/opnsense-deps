/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include <linux/version.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <net/pkt_sched.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/irqnr.h>
#include <linux/ppp_defs.h>
#include <linux/highmem.h>
#include <linux/proc_fs.h>
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
#include <net/xfrm.h>
#endif

#include <linux/spinlock.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>
#include "portdefs.h"
#include "dpa_ipsec.h"
#include "cdx_ioctl.h"
#include "cdx.h"
#include "misc.h"
#include "dpaa_eth_common.h"
#include "dpa_wifi.h"
#include "procfs.h"

/*
* DPA_FQ_TD_BYTES is frame queue tail drop bytes mode  threshold value. This 
* threshold is per frame queue.
*/
#define DPA_FQ_TD_BYTES	316000000

#ifdef DPA_IPSEC_OFFLOAD 
//#define DPA_IPSEC_DEBUG  	1
//#define DPA_IPSEC_TEST_ENABLE	1

#define DPAIPSEC_ERROR(fmt, ...)\
{\
        printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#define DPAIPSEC_INFO(fmt, ...)\
{\
        printk(KERN_INFO fmt, ## __VA_ARGS__);\
}

#define MAX_IPSEC_SA_INFO	16
#define IPSEC_WQ_ID		2

/*
* FQ_TAIL_DROP support for the tail drop support per frame queue base.
* It means based on the on the threshold(default is in bytes mode, DPA_FQ_TD_BYTES)
* value it drops the packet per frame queue. Basically this support framework is
* added only for "to sec ipsec" frame queues only. Now it is disabled, as CS_TAIL_DROP
* support is enabled and that is sufficient. To enable FQ_TAIL_DROP support uncomment
* below macro.
*/
//#define FQ_TAIL_DROP

/*
* CS_TAIL_DROP support for the tail drop support is per congestion group record.
* Each congestion group record can have multiple frame queues can group together.
* In our case all "to sec ipsec" frame queues are grouped into one congestion group.
* This threshold works on group all frame queues bytes at that moment. This also
* by default in bytes mode. It checks thresold with CDX_DPAA_INGRESS_CS_TD.
*/
#define CS_TAIL_DROP
#ifdef CS_TAIL_DROP
struct cgr_priv {
/*	bool use_ingress_cgr;*/
	struct qman_cgr ingress_cgr;
};
/* The following macro is used as default value before introducing module param */
#define CDX_DPAA_INGRESS_CS_TD	4000/*DPA_FQ_TD_BYTES*/ /*316000000*/

#define SEC_CONGESTION_DISABLE	0

unsigned int sec_congestion = SEC_CONGESTION_DISABLE;
module_param(sec_congestion, uint, S_IRUGO);
MODULE_PARM_DESC(sec_congestion, "0: congestion disable n: congestion threshold");

#endif

struct dpa_ipsec_sainfo {
	void *shdesc_mem;
	struct sec_descriptor *shared_desc;
	struct dpa_fq sec_fq[NUM_FQS_PER_SA];
	void *sa_proc_entry;
};

struct ipsec_info {
	uint32_t crypto_channel_id;
	int ofport_handle;
	uint32_t ofport_channel;
	uint32_t ofport_portid;
	void *ofport_td[MAX_MATCH_TABLES];
	uint32_t expt_fq_count ;
	struct dpa_bp *ipsec_bp;
	struct dpa_fq *pcd_fq;
	struct dpa_fq		*ipsec_exception_fq;
	struct port_bman_pool_info parent_pool_info;
#ifdef CS_TAIL_DROP
	struct cgr_priv	cgr;
#endif
};

static struct ipsec_info ipsecinfo;
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
extern struct xfrm_state *xfrm_state_lookup_byhandle(struct net *net, u16 handle);
#endif

struct dpa_bp* get_ipsec_bp(void)
{
	return (ipsecinfo.ipsec_bp);
}
struct sec_descriptor *get_shared_desc(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->shared_desc);
}

uint32_t get_fqid_to_sec(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_TO_SEC].fqid);
}

uint32_t get_fqid_from_sec(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_FROM_SEC].fqid);
}
struct qman_fq *get_from_sec_fq(void *handle)
{
	return (struct qman_fq *)&(((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_FROM_SEC]);
} 
struct qman_fq *get_to_sec_fq(void *handle)
{
	return (struct qman_fq *)&(((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_TO_SEC]);
} 

#ifdef UNIQUE_IPSEC_CP_FQID
uint32_t ipsec_get_to_cp_fqid(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_TO_CP].fqid);
}
#endif

static void dpa_ipsec_ern_cb(struct qman_portal *qm, struct qman_fq *fq,
		const struct qm_mr_entry *msg)
{
	DPAIPSEC_ERROR("%s::fqid %x(%d)\n", __FUNCTION__, fq->fqid, fq->fqid);
}


uint32_t ipsec_exception_pkt_cnt;
void print_ipsec_exception_pkt_cnt(void)
{
	printk("%s:: Ipsec offload slow path packet count = %d\n",__func__,ipsec_exception_pkt_cnt);

	ipsec_exception_pkt_cnt= 0;
}

void * cdx_get_xfrm_state_of_sa(void *dev, uint16_t handle)
{
	struct xfrm_state *x;
	struct net_device *netdev = (struct net_device *)dev;

	if ((x = xfrm_state_lookup_byhandle(dev_net(netdev), handle)) == NULL)
	{
		DPAIPSEC_ERROR("(%s)xfrm_state not found for handle %x\n",
				__FUNCTION__, handle);
		return NULL;
	}
	return x;
}

void cdx_dpa_ipsec_xfrm_state_dec_ref_cnt(void *xfrm_state)
{
	if (xfrm_state)
	{
		xfrm_state_put((struct xfrm_state *)xfrm_state);
	}
	return;
}

#ifdef UNIQUE_IPSEC_CP_FQID
extern 	struct net_device *get_netdev_of_SA_by_fqid(uint32_t fqid,
		uint16_t *sagd_pkt);
#endif /* UNIQUE_IPSEC_CP_FQID */
static enum qman_cb_dqrr_result ipsec_exception_pkt_handler(struct qman_portal *qm,
		struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	uint8_t *ptr;
	uint32_t len;
	struct sk_buff *skb;
	struct net_device *net_dev;
	struct dpa_bp *dpa_bp;
	struct dpa_priv_s               *priv;
	struct dpa_percpu_priv_s        *percpu_priv;
	unsigned short eth_type;
	unsigned short sagd_pkt;
	struct sec_path *sp;
	struct xfrm_state *x;
	struct timespec ktime;
#ifdef DPA_IPSEC_DEBUG1
	unsigned short sagd; 
#endif
	int use_gro;
	int *percpu_bp_cnt;
	unsigned short protocol;
	int no_l2_itf_dev;
	gro_result_t gro_result;
	const struct qman_portal_config *pc;
	struct dpa_napi_portal *np;;
	/* check SEC errors here */
#ifdef DPA_IPSEC_DEBUG1
	DPAIPSEC_INFO("%s::fqid %x(%d), bpid %d, len %d, \n offset %d sts %08x, cnt %d\n", __FUNCTION__,
			dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
			dq->fd.offset,dq->fd.status, ipsec_exception_pkt_cnt);

	/* for debugging */
	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr));
	printk("Dispalying parse result:\n");
	display_buff_data(ptr, 0x70);
#endif /* DPA_IPSEC_DEBUG1 */

	/* len = (dq->fd.length20 - 4); */
	len = dq->fd.length20;
	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);
#ifdef DPA_IPSEC_DEBUG1
	/* for debugging printing packet*/
	if (len >= 64)
	{
		display_buff_data(ptr, 64);
	}
	else
	{
		display_buff_data(ptr, len);
	} 
#endif /*DPA_IPSEC_DEBUG1 */
	/* 
	 * extract sagd from the end of packet. That sagd is used for two purpose.
	 * 1) After the Sec processes since a new buffer is used for decrypted input 
	 *    packets, the port information on which the orginal packet reached is lost.
	 *    When giving the packet to the stack this information is required. Earlier
	 *    we used a hardcoded logic of identifying one of the port as WAN port  by name
	 *    or adding ESP table to only one of the port in configuration file, and hard code 
	 *    that port as incoming ipsec packet before submitting the packet. With this change
	 *    now we store the incoing interface netdev structure in SA structure itself and 
	 *    extract incoming for by using the sagd copied into the end of packet.
	 *  2) We need dpa_priv pointer from the net_dev for calling dpaa_eth_napi_schedule ()
	 *     We do not want the complete pkt processing happen in irq context. 
	 *     dpaa_eth_napi_schedule () schdule a soft irq and ensure this function is called
	 *     again soft irq. 
	 *  3) We need to find xrfm state by using this sagd and put that into skb
	 *     beofe submitting into stack. If the there is a coresponding inbound 
	 *     ipsec policy only this packet will be allowed otherwise stack will
	 *     drop the packet.   
	 */
	dpa_bp = dpa_bpid2pool(dq->fd.bpid);
#ifdef UNIQUE_IPSEC_CP_FQID
	net_dev = get_netdev_of_SA_by_fqid(dq->fqid, &sagd_pkt);
#else
	memcpy(&sagd_pkt,(ptr+(len-2)),2);
	net_dev = (struct net_device *) M_ipsec_get_sa_netdev(sagd_pkt );
#endif /* UNIQUE_IPSEC_CP_FQID */

	if(!net_dev ){
#ifdef DPA_IPSEC_DEBUG
		DPAIPSEC_INFO("%s:: Could not find or delete mark set in inbound SA, droping pkt \n",__func__);
#endif
		goto rel_fd;
	}

	use_gro = net_dev->features & NETIF_F_GRO;
	if ((x = xfrm_state_lookup_byhandle(dev_net(net_dev), sagd_pkt )) == NULL)
	{
#ifdef DPA_IPSEC_DEBUG
		DPAIPSEC_INFO("%s(%d) xfrm_state not found. Dropping pkt\n", __func__,__LINE__);
#endif
		goto rel_fd;
	}

	priv = netdev_priv(net_dev); 
	DPA_BUG_ON(!priv);
	/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, qm)))
	{
		DPAIPSEC_ERROR("%s(%d) dpaa_eth_napi_schedule failed\n",
				__FUNCTION__,__LINE__);
		return qman_cb_dqrr_stop;
	}
#endif /* CONFIG_FSL_ASK_QMAN_PORTAL_NAPI */

	no_l2_itf_dev = vwd_is_no_l2_itf_device(net_dev);
	ipsec_exception_pkt_cnt++;
	percpu_bp_cnt =	raw_cpu_ptr(dpa_bp->percpu_count);
	/*  When V6 SA is applied to v4 packet and vice versa, since ether header is
	 *  copied from input packet, it will be wrong. Below logic is added just
	 *  make the required correction in this case.
	 */
	memcpy(&eth_type,(ptr+12),2);
	if((eth_type == htons(ETHERTYPE_IPV4)) && ((ptr[14] & 0xF0) == 0x60))
	{
		ptr[12]= 0x86;
		ptr[13] = 0xDD;
	}
	if((eth_type == htons(ETHERTYPE_IPV6)) && ((ptr[14] & 0xF0) == 0x40))
	{
		ptr[12]= 0x08;
		ptr[13] = 0x00;
	}
	protocol =  *((unsigned short*) (ptr + 12));
#ifdef DPA_IPSEC_DEBUG1
	DPAIPSEC_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d netdev %p dev %s temp_dev =%s addr %llx sts %08x\n", __FUNCTION__,
			dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
			dq->fd.offset, net_dev, net_dev->name,net_dev->name, (uint64_t)dq->fd.addr, dq->fd.status);
	DPAIPSEC_INFO(" sagd extracted from packet = %d \n",sagd_pkt);
	//display_buff_data(ptr, len);	
	//goto rel_fd;
#endif

	if (likely(dq->fd.format == qm_fd_contig)) {
		skb = contig_fd_to_skb(priv, &dq->fd, &use_gro);
	} else {
		skb = sg_fd_to_skb(priv, &dq->fd, &use_gro, percpu_bp_cnt);
		percpu_priv->rx_sg++;
	}

	(*percpu_bp_cnt)--;
	if (unlikely(dpaa_eth_refill_bpools(dpa_bp, percpu_bp_cnt,
			THRESHOLD_IPSEC_BPOOL_REFILL))) {
		//if we cant refill give this up
		goto pkt_drop;
	}



	skb->dev = net_dev;
//	skb_reset_tail_pointer(skb);
	if (no_l2_itf_dev)
	{
#ifndef UNIT_TEST
		skb_pull(skb, ETH_HLEN);
		skb_reset_network_header(skb);
		skb->mac_len = 0;
		skb->protocol = protocol;
#else
		skb->protocol = eth_type_trans(skb, net_dev);
#endif
	}
	else
	{
		skb->protocol = eth_type_trans(skb, net_dev);
	}

	sp = skb_ext_add(skb, SKB_EXT_SEC_PATH);

	if (!sp)
	{
		DPAIPSEC_ERROR("No sec_path. Dropping pkt\n");
		goto pkt_drop;
	}

	sp->xvec[0] = x;

	if (!x->curlft.use_time)
	{
		getnstimeofday(&ktime);
		x->curlft.use_time = (unsigned long)ktime.tv_sec;
	}
	sp->len = 1;

#ifdef DPA_IPSEC_DEBUG1
	DPAIPSEC_INFO("%s::len %d ipsec_exception_pkt_cnt %d\n", 
			__FUNCTION__, skb->len, ipsec_exception_pkt_cnt);
#endif
	/* netif_receive_skb(skb); */
	if (use_gro)
	{
		pc = qman_p_get_portal_config(qm);
		np = &percpu_priv->np[pc->index];

		np->p = qm;
		gro_result = napi_gro_receive(&np->napi, skb);
		/* If frame is dropped by the stack, rx_dropped counter is
		 * incremented automatically, so no need for us to update it
		 */
		if (unlikely(gro_result == GRO_DROP))
			goto pkt_drop;

	}
	else if ( (netif_receive_skb(skb) == NET_RX_DROP)) /* (netif_rx(skb) != NET_RX_SUCCESS) */
		DPAIPSEC_ERROR("%s::packet dropped\n", __FUNCTION__);
	return qman_cb_dqrr_consume;
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
pkt_drop:
#endif
	if (skb) 
		dev_kfree_skb(skb);
rel_fd:
	dpa_fd_release(net_dev, &dq->fd);
	return qman_cb_dqrr_consume;
}


#define PORTID_SHIFT_VAL 8

int cdx_find_ipsec_pcd_fqinfo(int fqid, struct ipsec_info *info)
{
	struct dpa_fq *list = info->ipsec_exception_fq;
	while (list)
	{
		if (list->fqid == fqid)
			return 0;
		list = (struct dpa_fq *)list->list.next;
	}
	return -1;
}

void ipsec_addfq_to_exceptionfq_list(struct dpa_fq *frameq,
		struct ipsec_info *info)
{
	frameq->list.next = (struct list_head *)info->ipsec_exception_fq;
	info->ipsec_exception_fq = frameq;
}

void ipsec_delfq_from_exceptionfq_list(uint32_t fqid,
		struct ipsec_info *info)
{
	struct dpa_fq *prev, *list = info->ipsec_exception_fq;
	prev = list;
	while (list)
	{
		if (list->fqid == fqid)
		{
			if (prev == list)
			{
				info->ipsec_exception_fq = (struct dpa_fq *)list->list.next;
				return;
			}
			prev->list.next = list->list.next;
			return;
		}
		prev = list;
		list = (struct dpa_fq *)list->list.next;
	}
	return;
}

static int create_ipsec_pcd_fqs(struct ipsec_info *info, uint32_t schedule)
{
	struct dpa_fq *dpa_fq;
	uint32_t fqbase;
	uint32_t fqcount;
	uint32_t portid;
	uint32_t ii,jj;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals, max_dist = 0;
	uint32_t next_portal_ch_idx;
	const cpumask_t *affine_cpus;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	struct dpa_iface_info *oh_iface_info;

	//get cpu portal channel info
	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}
	if (!num_portals) {
		DPAIPSEC_ERROR("%s::unable to get affined portal info\n",
				__FUNCTION__);
		return -1;
	}

#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::num_portals %d ::", __FUNCTION__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPAIPSEC_INFO("%d ", portal_channel[ii]);
	DPAIPSEC_INFO("\n");
#endif

	if (get_ofport_max_dist(IPSEC_FMAN_IDX, info->ofport_handle, &max_dist) < 0)
	{
		DPAIPSEC_ERROR("%s::unable to get distributions for oh port\n", __FUNCTION__);
		return -1;
	}

	DPAIPSEC_INFO("%s::max_dist : %d\n", __FUNCTION__, max_dist) ;

	/* create all FQs */
	info->expt_fq_count = 0;
	/* get port id required for FQ creation */
	if (get_ofport_portid(IPSEC_FMAN_IDX, info->ofport_handle, &portid)) {
		DPAIPSEC_ERROR("%s::err getting of port id\n", __FUNCTION__) ;
		return -1;
	}

	if ((oh_iface_info = dpa_get_ohifinfo_by_portid(portid)) == NULL) {
		DPAIPSEC_ERROR("%s::err getting oh iface info of port id %u\n", __FUNCTION__, portid) ;
		return -1;
	}
	if (oh_iface_info->pcd_proc_entry == NULL)
	{
		DPAIPSEC_ERROR("%s()::%d OH iface pcd proc entry is invalid:\n", __func__, __LINE__);
		return -1;
	}

	for (jj = 0; jj < max_dist; jj++)
	{
		/* get FQbase and count used for each distribution
			 with scheme sharing this is the only distribution that will be used */

		if (get_oh_port_pcd_fqinfo(IPSEC_FMAN_IDX, info->ofport_handle,
					jj , &fqbase, &fqcount)) {
			DPAIPSEC_ERROR("%s::err getting pcd fqinfo for dist %d\n",
					__FUNCTION__,jj) ;
			return FAILURE;
		}

		/* add port id into FQID */
		fqbase |= (portid << PORTID_SHIFT_VAL);

		DPAIPSEC_INFO("%s::pcd FQ base for portid %d and  distribution id(%d): %x(%d), count %d\n",
				__FUNCTION__, portid, jj, fqbase, fqbase, fqcount);

		for (ii = 0; ii < fqcount; ii++)
		{
			DPAIPSEC_INFO("%s(%d) calling cdx_find_ipsec_pcd_fqinfo (%x)\n",
					__FUNCTION__,__LINE__, fqbase);
			if (!cdx_find_ipsec_pcd_fqinfo(fqbase, info))
			{
				fqbase++;
				continue;
			}

			/* create FQ for exception packets from ipsec ofline  port */
			dpa_fq = kzalloc((sizeof(struct dpa_fq)),1);
			if (!dpa_fq) {
				DPAIPSEC_ERROR("%s::unable to alloc mem for dpa_fq\n", __FUNCTION__) ;
				return FAILURE;
			}

			/* set FQ parameters */
			/* use wan port as the device for this FQ */
			//dpa_fq->net_dev = net_dev;
			dpa_fq->fq_type = FQ_TYPE_RX_PCD;
			dpa_fq->fqid = fqbase;
			/* set call back function pointer */
			fq = &dpa_fq->fq_base;
			fq->cb.dqrr = ipsec_exception_pkt_handler;
			/* round robin channel like ethernet driver does */
			dpa_fq->channel = portal_channel[next_portal_ch_idx];
			if (next_portal_ch_idx == (num_portals - 1))
				next_portal_ch_idx = 0;
			else
				next_portal_ch_idx++;
			dpa_fq->wq = DEFA_WQ_ID;
			ipsec_addfq_to_exceptionfq_list(dpa_fq,info);
			/* set options similar to ethernet driver */
			memset(&opts, 0, sizeof(struct qm_mcc_initfq));
			opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
			opts.fqd.context_a.stashing.exclusive =
				(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
			opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
			opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
			/* create FQ */
			if (qman_create_fq(dpa_fq->fqid, 0, fq)) {
				DPAIPSEC_ERROR("%s::qman_create_fq failed for fqid %d\n",
						__FUNCTION__, dpa_fq->fqid);
				goto err_ret;
			}
			opts.fqid = dpa_fq->fqid;
			opts.count = 1;
			opts.fqd.dest.channel = dpa_fq->channel;
			opts.fqd.dest.wq = dpa_fq->wq;
			opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
					QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
			if (schedule)
				schedule = QMAN_INITFQ_FLAG_SCHED;

			/* init FQ */
			if (qman_init_fq(fq, schedule, &opts)) {
				DPAIPSEC_ERROR("%s::qman_init_fq failed for fqid %d\n",
						__FUNCTION__, dpa_fq->fqid);
				qman_destroy_fq(fq, 0);
				goto err_ret;
			}
			cdx_create_type_fqid_info_in_procfs(fq, PCD_DIR, oh_iface_info->pcd_proc_entry, NULL);
#ifdef DPA_IPSEC_DEBUG
			DPAIPSEC_INFO("%s::created pcd fq %x(%d) for wlan packets "
					"channel 0x%x\n", __FUNCTION__,
					dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
			/* next FQ */
			fqbase++;
			info->expt_fq_count++;
		}
	}
	return SUCCESS;
err_ret:
	/* release FQs allocated so far and mem */
	return FAILURE;
}

static int create_ipsec_fqs(struct dpa_ipsec_sainfo *ipsecsa_info, uint32_t schedule, uint32_t handle)
{
	int32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	int errno;
	uint32_t flags = 0;
	uint64_t addr;
#ifdef UNIQUE_IPSEC_CP_FQID
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals;
	uint32_t next_portal_ch_idx;
	const cpumask_t *affine_cpus;
	uint32_t fqids_base;
#endif /* UNIQUE_IPSEC_CP_FQID */
	int to_sec_fq = 0;
	uint8_t sa_id_name[8]="";

	//get cpu portal channel info
#ifdef UNIQUE_IPSEC_CP_FQID
	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
		/* need only one channel for one frame queue */
		break;
	}
	if (!num_portals) {
		DPAIPSEC_ERROR("%s::unable to get affined portal info\n",
				__FUNCTION__);
		return -1;
	}

#ifdef DPA_IPSEC_DEBUG1
	DPAIPSEC_INFO("%s::num_portals %d ::", __FUNCTION__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPAIPSEC_INFO("%d ", portal_channel[ii]);
	DPAIPSEC_INFO("\n");
#endif

#endif /* UNIQUE_IPSEC_CP_FQID */


	ipsecsa_info->shdesc_mem = 
		kzalloc((sizeof(struct sec_descriptor) + PRE_HDR_ALIGN), GFP_KERNEL);
	if (!ipsecsa_info->shdesc_mem)
	{
		DPAIPSEC_ERROR("%s::kzalloc failed for SEC descriptor\n",
				__FUNCTION__);
		goto err_ret0;
	}
	memset(ipsecsa_info->shdesc_mem, 0, (sizeof(struct sec_descriptor)+PRE_HDR_ALIGN));
	ipsecsa_info->shared_desc = (struct sec_descriptor *)
		PTR_ALIGN(ipsecsa_info->shdesc_mem, PRE_HDR_ALIGN);

#ifdef UNIQUE_IPSEC_CP_FQID
	errno = qman_alloc_fqid_range(&fqids_base, NUM_FQS_PER_SA, 0, 0);
	if (errno < NUM_FQS_PER_SA)
	{
		DPAIPSEC_ERROR("%s::qman_alloc_fqid_range failed for allocating frame queues\n",
				__FUNCTION__);
		goto err_ret1;
	}
#endif /* UNIQUE_IPSEC_CP_FQID */

	sprintf(sa_id_name, "0x%x", handle);
	if (cdx_create_dir_in_procfs(&ipsecsa_info->sa_proc_entry, sa_id_name, SA_DIR)) {
		DPAIPSEC_ERROR("%s:: create pcd proc entry failed %s\n", 
				__FUNCTION__, sa_id_name);
		goto err_ret2;
	}

	for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {

		dpa_fq = &ipsecsa_info->sec_fq[ii];
		memset(dpa_fq, 0, sizeof(struct dpa_fq));
		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		fq = &dpa_fq->fq_base;
		to_sec_fq = 0;
		switch (ii) {
			case FQ_FROM_SEC:
				{
#ifdef DPA_IPSEC_DEBUG
					printk("%s::handle %x\n", __FUNCTION__, handle);
#endif
#ifdef UNIQUE_IPSEC_CP_FQID
					flags = QMAN_FQ_FLAG_TO_DCPORTAL;
#else
					flags = (QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_DYNAMIC_FQID);
#endif /* UNIQUE_IPSEC_CP_FQID */
					dpa_fq->channel = ipsecinfo.ofport_channel;
					/* setting A1 value to 2 and setting a  bit to copy A1 value in  context A field  */
					/* setting override frame queue option */
					opts.fqd.context_a.hi = 
						(((
#ifdef UNIQUE_IPSEC_CP_FQID
							 CDX_FQD_CTX_A_OVERRIDE_FQ |
							 /*CDX_FQD_CTX_A_B0_FIELD_VALID | */
#endif /* UNIQUE_IPSEC_CP_FQID */
							 CDX_FQD_CTX_A_A1_FIELD_VALID) <<
							CDX_FQD_CTX_A_SHIFT_BITS) |
						 CDX_FQD_CTX_A_A1_VAL_TO_CHECK_SECERR );
#ifdef UNIQUE_IPSEC_CP_FQID
					opts.fqd.context_b = fqids_base + FQ_TO_CP;
#endif /* UNIQUE_IPSEC_CP_FQID */
					break;
				}
			case FQ_TO_SEC:
				{
#ifdef UNIQUE_IPSEC_CP_FQID
					flags = QMAN_FQ_FLAG_TO_DCPORTAL;
#else
					flags = (QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_DYNAMIC_FQID);
#endif /* UNIQUE_IPSEC_CP_FQID */
					addr = virt_to_phys(ipsecsa_info->shared_desc);
					dpa_fq->channel = ipsecinfo.crypto_channel_id;
					dpa_fq->fq_base.cb.ern = dpa_ipsec_ern_cb;
					opts.fqd.context_b = ipsecsa_info->sec_fq[FQ_FROM_SEC].fqid;
					opts.fqd.context_a.hi = (uint32_t) (addr >> 32);
					opts.fqd.context_a.lo = (uint32_t) (addr);
					to_sec_fq = 1;
					break;
				}
#ifdef UNIQUE_IPSEC_CP_FQID
			case FQ_TO_CP:
				{
					flags = 0;
					/* set FQ parameters */
					/* dpa_fq->net_dev = net_dev; */
					/* No net_dev is attached to FQ as its being fetched from sagd */
					dpa_fq->fq_type = FQ_TYPE_RX_PCD;
					/* creating CP fqid as the fqid value of FROM_SEC FQID +1 */
					/* set call back function pointer */
					dpa_fq->fq_base.cb.dqrr = ipsec_exception_pkt_handler;
					/* round robin channel like ethernet driver does */
					dpa_fq->channel = portal_channel[next_portal_ch_idx];
					break;
				}
#endif /* UNIQUE_IPSEC_CP_FQID */

		}
		dpa_fq->wq = IPSEC_WQ_ID;
#ifdef UNIQUE_IPSEC_CP_FQID
		if (qman_create_fq(fqids_base+ii, flags, fq)) 
#else
		if (qman_create_fq(dpa_fq->fqid, flags, fq)) 
#endif /* UNIQUE_IPSEC_CP_FQID */
		{
			DPAIPSEC_ERROR("%s::qman_create_fq failed for fqid %d\n",
					__FUNCTION__, dpa_fq->fqid);
			goto err_ret3;
		}
		dpa_fq->fqid = fq->fqid;
		opts.fqid = dpa_fq->fqid;
		opts.count = 1;
		opts.fqd.dest.channel = dpa_fq->channel;
		opts.fqd.dest.wq = dpa_fq->wq;
#ifndef UNIQUE_IPSEC_CP_FQID
		opts.fqd.fq_ctrl = QM_FQCTRL_CPCSTASH;
#else
		if (ii != FQ_TO_CP)
		{
			opts.fqd.fq_ctrl = QM_FQCTRL_CPCSTASH;
		}
		else
		{
			opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
			opts.fqd.context_a.stashing.exclusive =
				(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
			opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
			opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
		}
#endif /* UNIQUE_IPSEC_CP_FQID */
		if (to_sec_fq == 1)
		{
#ifdef FQ_TAIL_DROP
			/* Enabling the FQ tail drop threshold */
			opts.we_mask = QM_INITFQ_WE_TDTHRESH;
			/* Setting the frame queue tail drop threshold value. */
			qm_fqd_taildrop_set(&opts.fqd.td, DPA_FQ_TD_BYTES, 1);
			/* Enabling the FQ tail drop support. */
			opts.fqd.fq_ctrl |= QM_FQCTRL_TDE;
#endif
#ifdef CS_TAIL_DROP
			if (sec_congestion)
			{
				/* CS tail drop start*/
				opts.we_mask |= QM_INITFQ_WE_CGID;
				/* Enabling the congestion group */
				opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
				/* setting congestion group record id, which is created at the time of initialization. */
				opts.fqd.cgid = (u8)ipsecinfo.cgr.ingress_cgr.cgrid;
				/* CS tail drop end*/
			}
#endif
		}
		opts.we_mask |= (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
		if(schedule)
			schedule = QMAN_INITFQ_FLAG_SCHED;
		if((errno=qman_init_fq(fq, schedule, &opts)))
		{
			DPAIPSEC_ERROR("%s::qman_init_fq failed for fqid %d errno= %d\n",
					__FUNCTION__, dpa_fq->fqid,errno);
			qman_destroy_fq(fq, 0);
			goto err_ret4;
			return FAILURE;
		}
		ipsec_addfq_to_exceptionfq_list(dpa_fq, &ipsecinfo);

		if (ii == FQ_FROM_SEC)
		{
			cdx_create_type_fqid_info_in_procfs(fq, SA_DIR, ipsecsa_info->sa_proc_entry, "from_sec");
		}
		else if (ii == FQ_TO_SEC)
		{
			cdx_create_type_fqid_info_in_procfs(fq, SA_DIR, ipsecsa_info->sa_proc_entry, "to_sec");
		}
#ifdef UNIQUE_IPSEC_CP_FQID
		else if (ii == FQ_TO_CP)
		{
			cdx_create_type_fqid_info_in_procfs(fq, SA_DIR, ipsecsa_info->sa_proc_entry, "to_cp");
		}
#endif

#ifdef DPA_IPSEC_DEBUG
		DPAIPSEC_INFO("%s::created fq %x(%d) for ipsec - type %d "
				"channel 0x%x\n", __FUNCTION__,
				dpa_fq->fqid, dpa_fq->fqid, ii, dpa_fq->channel);
#endif
	}
	return SUCCESS;

err_ret4:
err_ret3:
	for (; ii>0 ; ii--)
	{
		fq = &(ipsecsa_info->sec_fq[ii-1].fq_base);
		ipsec_delfq_from_exceptionfq_list(fq->fqid,&ipsecinfo);
		if (qman_retire_fq(fq, NULL)) {
			DPAIPSEC_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			return FAILURE;
		}
		if (qman_oos_fq(fq)) {
			DPAIPSEC_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			return FAILURE;
		}
		cdx_remove_fqid_info_in_procfs(fq->fqid);
		qman_destroy_fq(fq, 0);
	}
	if (ipsecsa_info->sa_proc_entry)
		proc_remove(((cdx_proc_dir_entry_t *)(ipsecsa_info->sa_proc_entry))->proc_dir);
err_ret2:
#ifdef UNIQUE_IPSEC_CP_FQID
	/*TODO : qman_release_fqid_range */
err_ret1:
#endif
	kfree(ipsecsa_info->shdesc_mem);
err_ret0:
	return FAILURE;
}

void display_fq_info(void *handle)
{
	struct dpa_ipsec_sainfo *ipsecsa_info;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcr_queryfq_np *np;
	struct qm_fqd *fqd;
	uint32_t ii;

	ipsecsa_info = (struct dpa_ipsec_sainfo *)handle;
	np = kzalloc(sizeof(struct qm_mcr_queryfq_np), GFP_KERNEL);
	if (!np) {
		printk("%s::error allocating fqnp\n", __FUNCTION__);
		return;
	}
	fqd = kzalloc(sizeof(struct qm_fqd), GFP_KERNEL);
	if (!fqd) {
		printk("%s::error allocating fqd\n", __FUNCTION__);
		kfree(np);
		return;
	}

	for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {
		dpa_fq = &ipsecsa_info->sec_fq[ii];
		fq = &dpa_fq->fq_base;
		printk("===========================================\n%s::fqid %x(%d\n", __FUNCTION__, fq->fqid, fq->fqid);
		if (qman_query_fq(fq, fqd)) {
			printk("%s::error getting fq fields\n", __FUNCTION__);
			break;
		}
		printk("fqctrl\t%x\n", fqd->fq_ctrl);
		printk("channel\t%x\n", fqd->dest.channel);
		printk("Wq\t%d\n", fqd->dest.wq);
		printk("contextb\t%x\n", fqd->context_b);
		printk("contexta\t%p\n", (void *)fqd->context_a.opaque);
		if (qman_query_fq_np(fq, np)) {
			printk("%s::error getting fqnp fields\n", __FUNCTION__);
			break;
		}
		printk("state\t%d\n", np->state);
		printk("byte count\t%d\n", np->byte_cnt);
		printk("frame count\t%d\n", np->frm_cnt);
	}
	kfree(np);
	kfree(fqd);
}


static int ipsec_init_ohport(struct ipsec_info *info)
{

	/* Get OH port for this driver */
	info->ofport_handle = alloc_offline_port(IPSEC_FMAN_IDX, PORT_TYPE_IPSEC, 
			NULL, NULL);
	if (info->ofport_handle < 0)
	{
		DPAIPSEC_ERROR("%s: Error in allocating OH port Channel\n", __FUNCTION__);
		return FAILURE;
	}
#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s: allocated oh port %d\n", __FUNCTION__, info->ofport_handle);
#endif
	if (get_ofport_info(IPSEC_FMAN_IDX, info->ofport_handle, &info->ofport_channel, 
				&info->ofport_td[0])) {
		DPAIPSEC_ERROR("%s: Error in getting OH port info\n", __FUNCTION__);
		return FAILURE;
	}
	if (get_ofport_portid(IPSEC_FMAN_IDX, info->ofport_handle, &info->ofport_portid)) {
		DPAIPSEC_ERROR("%s: Error in getting OH port id\n", __FUNCTION__);
		return FAILURE;
	}
	printk("%s:: ipsec of port id = %d\n ", __func__, info->ofport_portid);
	return SUCCESS;
}

void *  dpa_get_ipsec_instance(void)
{
	return &ipsecinfo; 
}

int dpa_ipsec_ofport_td(struct ipsec_info *info, uint32_t table_type, void **td, 
		uint32_t* portid)
{
	if (table_type >= MAX_MATCH_TABLES) {
		DPAIPSEC_ERROR("%s::invalid table type %d\n", __FUNCTION__, table_type);
		return FAILURE;
	}
	*td = info->ofport_td[table_type];
	*portid = info->ofport_portid;
	return SUCCESS;
}

extern int dpaa_bp_alloc_n_add_buffs(const struct dpa_bp *dpa_bp, 
		uint32_t nbuffs, bool act_skb);
#define CDX_MAX_SG_BUFF_SIZE 1024
#define CDX_MAX_SG_BUFF_COUNT 512
extern struct dpa_bp *sg_bpool_g; // buffer reqd to frame SG list for skb fraglist
extern struct dpa_bp *skb_2bfreed_bpool_g; //if no recyclable skbs exist in skb fraglist, those should be freed back, SEC engine will add to this bman pool

int cdx_init_skb_2bfreed_bpool(void)
{
	struct dpa_bp *bp, *bp_parent;
	struct port_bman_pool_info parent_pool_info;

	// allocate memory for bpool
	bp = kzalloc(sizeof(struct dpa_bp), 0);
	if (unlikely(bp == NULL)) {
		DPAIPSEC_ERROR("%s(%d)::failed to mem for non_recyclable SKB free bman pool\n",
				__FUNCTION__,__LINE__);
		return -1;
	}
	bp->size = CDX_MAX_SG_BUFF_SIZE;
	bp->config_count = CDX_MAX_SG_BUFF_COUNT;

	//find pools used by ethernet devices
	if (get_phys_port_poolinfo_bysize(bp->size, &parent_pool_info)) {
		DPAIPSEC_ERROR("%s::failed to locate eth bman pool for ipsec\n", 
				__FUNCTION__);
		kfree(bp);
		return -1;
	}
	bp_parent = dpa_bpid2pool(parent_pool_info.pool_id);
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAIPSEC_ERROR("%s::dpa_bp_alloc failed for bufpool of freeing skbs\n", 
				__FUNCTION__);
		kfree(bp);
		return -1;
	}
	DPAIPSEC_INFO("%s::bp->size :%zu, bpid %d\n", 
			__FUNCTION__, bp->size, bp->bpid);
	skb_2bfreed_bpool_g = bp;
	return 0;
}

int cdx_init_scatter_gather_bpool(void)
{
	struct dpa_bp *bp,*bp_parent;
	struct port_bman_pool_info parent_pool_info;
	int ret =0;

	bp = kzalloc(sizeof(struct dpa_bp), 0);
	if (unlikely(bp == NULL)) {
		DPAIPSEC_ERROR("%s::failed to allocate mem for SG bman pool\n", 
				__FUNCTION__);
		return -1;
	}
	bp->size = CDX_MAX_SG_BUFF_SIZE;
	bp->config_count = CDX_MAX_SG_BUFF_COUNT;

	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(bp->size, &parent_pool_info)) {
		DPAIPSEC_ERROR("%s::failed to locate eth bman pool for ipsec\n", 
				__FUNCTION__);
		kfree(bp);
		return -1;
	}
	bp_parent = dpa_bpid2pool(parent_pool_info.pool_id);
#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::parent bman pool for SG - bp %p, bpid %d paddr %lx vaddr %p dev %p\n", 
			__FUNCTION__, bp, parent_pool_info.pool_id,
			(unsigned long)bp->paddr, bp->vaddr, bp->dev);
#endif
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAIPSEC_ERROR("%s::dpa_bp_alloc failed for ipsec\n", 
				__FUNCTION__);
		kfree(bp);
		return -1;
	}
	DPAIPSEC_INFO("%s::bp->size :%zu, bpid %d\n", 
			__FUNCTION__, bp->size, bp->bpid);
	sg_bpool_g = bp;

	ret = dpaa_bp_alloc_n_add_buffs(bp, CDX_MAX_SG_BUFF_COUNT, 0);
	DPAIPSEC_INFO("%s(%d) buffers added to ipsec pool %d info size %zu \n", 
			__FUNCTION__,__LINE__,sg_bpool_g->bpid,
			sg_bpool_g->size);
	return 0;
}

static int add_ipsec_bpool(struct ipsec_info *info)
{
	struct dpa_bp *bp,*bp_parent;
	//int buffer_count = 0, ret = 0, refill_cnt ;
	//int ret =0;
	printk (KERN_INFO"\n ################## %s", 
			__FUNCTION__);

	bp = kzalloc(sizeof(struct dpa_bp), 0);
	if (unlikely(bp == NULL)) {
		DPAIPSEC_ERROR("%s::failed to allocate mem for bman pool for ipsec\n", 
				__FUNCTION__);
		return -1;
	}

	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(1700, &info->parent_pool_info)) {
		DPAIPSEC_ERROR("%s::failed to locate eth bman pool for ipsec\n", 
				__FUNCTION__);
		kfree(bp);
		return -1;
	}
	bp_parent = dpa_bpid2pool(info->parent_pool_info.pool_id);
#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::parent bman pool for ipsec - bp %p, bpid %d paddr %lx vaddr %p dev %p\n", 
			__FUNCTION__, bp, info->parent_pool_info.pool_id,
			(unsigned long)bp->paddr, bp->vaddr, bp->dev);
#endif
	bp->dev = bp_parent->dev;
	bp->percpu_count = devm_alloc_percpu(bp->dev, *bp->percpu_count);
	bp->size = IPSEC_BUFSIZE;
	bp->config_count = IPSEC_BUFCOUNT;
	bp->seed_cb = dpa_bp_priv_seed;
	bp->free_buf_cb = _dpa_bp_free_pf;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAIPSEC_ERROR("%s::dpa_bp_alloc failed for ipsec\n", 
				__FUNCTION__);
		kfree(bp);
		return -1;
	}
	DPAIPSEC_INFO("%s::bp->size :%zu, bpid %d\n", 
			__FUNCTION__, bp->size, bp->bpid);
	printk (KERN_INFO"\n ################## %s::bp->size :%zu, bpid %d\n", 
			__FUNCTION__, bp->size, bp->bpid);
	info->ipsec_bp = bp;

#if 0 // instead allocate max 64k size buffers and add bman

	while (buffer_count < IPSEC_BUFCOUNT)
	{
		refill_cnt = 0;
		ret = dpaa_eth_refill_bpools(bp, &refill_cnt);
		if (ret < 0)
		{
			DPAIPSEC_ERROR("%s:: Error returned for dpaa_eth_refill_bpools %d\n", __FUNCTION__,ret);
			break;
		}

		buffer_count += refill_cnt;
	}

	info->ipsec_bp->size =  bp_parent->size; 
	DPAIPSEC_INFO("%s::%d buffers added to ipsec pool %d info size %d parent pool size %d\n", 
			__FUNCTION__, buffer_count, info->ipsec_bp->bpid,
			info->parent_pool_info.buf_size,(int) bp_parent->size);
//#else
	ret = dpaa_bp_alloc_n_add_buffs(bp, IPSEC_BUFCOUNT, 1);
	DPAIPSEC_INFO("%s(%d) buffers added to ipsec pool %d info size %zu \n", 
			__FUNCTION__,__LINE__,info->ipsec_bp->bpid,
			info->ipsec_bp->size);
#endif
	return 0;
}
static int release_ipsec_bpool(struct ipsec_info *info)
{
	struct dpa_bp *bp =  info->ipsec_bp ;
	bman_free_pool(bp->pool);
	kfree(bp);
	info->ipsec_bp = NULL; 
	return 0;
}

int cdx_dpa_get_ipsec_pool_info(uint32_t *bpid, uint32_t *buf_size)
{
	if (!ipsecinfo.ipsec_bp) 	
		return -1;
	*bpid = ipsecinfo.ipsec_bp->bpid;
	//*buf_size =ipsecinfo.parent_pool_info.buf_size;
	*buf_size = ipsecinfo.ipsec_bp->size;
	return 0;

}

void *cdx_dpa_ipsecsa_alloc(struct ipsec_info *info, uint32_t handle) 
{
	struct dpa_ipsec_sainfo *sainfo;

	sainfo = (struct dpa_ipsec_sainfo *)
		kzalloc(sizeof(struct dpa_ipsec_sainfo), GFP_KERNEL);
	if (!sainfo) {
		DPAIPSEC_ERROR("%s::Error in allocating sainfo\n", 
				__FUNCTION__);
		return NULL;
	}	
	memset(sainfo, 0, sizeof(struct dpa_ipsec_sainfo));
	//create fqs in scheduled state
	if (create_ipsec_fqs(sainfo, 1, handle)) {
		kfree(sainfo);
		return NULL;
	}
	return sainfo; 	
}

/* change the state of frame queues */
int cdx_dpa_ipsec_retire_fq(void *handle, int fq_num)
{
	struct dpa_ipsec_sainfo *sainfo;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	int32_t flags, ret;

	sainfo = (struct dpa_ipsec_sainfo *)handle;
	dpa_fq = &sainfo->sec_fq[fq_num];
	fq = &dpa_fq->fq_base; 
	ret = qman_retire_fq(fq, &flags);
	if (ret < 0) {
		DPAIPSEC_ERROR("%s::Failed to retire FQ %x(%d)\n", 
				__FUNCTION__, fq->fqid, fq->fqid);
	}
	return ret;
}

int cdx_dpa_ipsecsa_release(void *handle) 
{
	struct dpa_ipsec_sainfo *sainfo;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	uint32_t ii;
	//	uint32_t flags;

	if (!handle)
		return FAILURE;
	sainfo = (struct dpa_ipsec_sainfo *)handle;

	for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {
		dpa_fq = &sainfo->sec_fq[ii];
		fq = &dpa_fq->fq_base; 
		ipsec_delfq_from_exceptionfq_list(fq->fqid,&ipsecinfo);
#if 0 /* calling retire before timer start */
		//drain fq TODO
		//take fqs out of service
		if (qman_retire_fq(fq, &flags)) {
			DPAIPSEC_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			return FAILURE;
		}
#endif /* 0 */
		if (qman_oos_fq(fq)) {
			DPAIPSEC_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			return FAILURE;
		}
		cdx_remove_fqid_info_in_procfs(fq->fqid);
		qman_destroy_fq(fq, 0);
	}
	if (sainfo->sa_proc_entry)
	{
		proc_remove(((cdx_proc_dir_entry_t *)(sainfo->sa_proc_entry))->proc_dir);
	}
#ifdef  UNIQUE_IPSEC_CP_FQID
	qman_release_fqid_range(sainfo->sec_fq[FQ_FROM_SEC].fqid, NUM_FQS_PER_SA);
#endif /* UNIQUE_IPSEC_CP_FQID */
	kfree(sainfo);
	return SUCCESS;
}

int cdx_ipsec_sa_fq_check_if_retired_state(void *dpa_ipsecsa_handle, int fq_num)
{
	struct dpa_ipsec_sainfo *sainfo;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	sainfo = (struct dpa_ipsec_sainfo *)dpa_ipsecsa_handle;
	dpa_fq = &sainfo->sec_fq[fq_num];
	fq = &dpa_fq->fq_base; 
	/* if fq is not in retired state, restart timer */
	return (fq->state != qman_fq_state_retired);
}
#ifdef DPA_IPSEC_TEST_ENABLE
void dpa_ipsec_test(struct ipsec_info *info)
{
	void *handle;	
	struct sec_descriptor *sh_desc;
	uint32_t tosec_fqid;
	uint32_t fromsec_fqid;
	uint32_t portid;
	void *td;

	if (cdx_dpa_ipsec_wanport_td(info, ESP_IPV4_TABLE, &td)) {
		return;
	}	
	DPAIPSEC_INFO("%s::WAN ESP_IPV4_TABLE %p\n", __FUNCTION__, td);

	if (cdx_dpa_ipsec_wanport_td(info, ESP_IPV6_TABLE, &td)) {
		return;
	}	
	DPAIPSEC_INFO("%s::WAN ESP_IPV6_TABLE %p\n", __FUNCTION__, td);

	if (dpa_ipsec_ofport_td(info, IPV4_UDP_TABLE, &td, &portid)) {
		return;
	}	
	DPAIPSEC_INFO("%s::OF IPV4_TCPUDP_TABLE %p\n", __FUNCTION__, td);

	if (dpa_ipsec_ofport_td(info, IPV6_UDP_TABLE, &td, &portid )) {
		return;
	}	
	DPAIPSEC_INFO("%s::OF IPV6_TCPUDP_TABLE %p\n", __FUNCTION__, td);

	if (dpa_ipsec_ofport_td(info, ESP_IPV4_TABLE, &td, &portid)) {
		return;
	}	
	DPAIPSEC_INFO("%s::OF ESP_IPV4_TABLE %p, portif = %d\n", __FUNCTION__, td, portid);

	if (dpa_ipsec_ofport_td(info, ESP_IPV6_TABLE, &td, &portid)) {
		return;
	}	
	DPAIPSEC_INFO("%s::OF ESP_IPV6_TABLE %p\n", __FUNCTION__, td);

	handle = cdx_dpa_ipsecsa_alloc(info, 0xaa55);
	if (handle) {
		sh_desc = get_shared_desc(handle);
		tosec_fqid = get_fqid_to_sec(handle);	
		fromsec_fqid = get_fqid_from_sec(handle);	
		DPAIPSEC_INFO("%s::sh desc %p, tosec fqid %x(%d) from sec fqid %x(%d)\n",
				__FUNCTION__, sh_desc, tosec_fqid, tosec_fqid,
				fromsec_fqid, fromsec_fqid); 
		if (cdx_dpa_ipsecsa_release(handle)) {
			DPAIPSEC_ERROR("%s::Failed to release sa %p\n", 
					__FUNCTION__, handle);
			return;
		}		
	} else {
		DPAIPSEC_ERROR("%s::Failed to alloc sa\n", __FUNCTION__);
		return;
	}
}
#else
#define dpa_ipsec_test(x)
#endif

#ifdef CS_TAIL_DROP
static void cgr_cb(struct qman_portal *qm, struct qman_cgr *cgr, int congested)
{
	static u32 no_of_cong_entry = 0;
#define PRINT_DURATION 500000

#ifdef DPA_IPSEC_DEBUG
	if (congested) {
		if (((no_of_cong_entry/2) % PRINT_DURATION) == 0)
			printk("%s()::%d entered congestion %d\n", __func__, __LINE__, no_of_cong_entry);

	} else {
		if (((no_of_cong_entry/2) % PRINT_DURATION) == 0)
			printk("%s()::%d EXITED congestion %d.\n", __func__, __LINE__, no_of_cong_entry);
	}
#endif
	++no_of_cong_entry;
	return;
}

static int cdx_dpaa_ingress_cgr_init(struct cgr_priv *cgr)
{
	struct qm_mcc_initcgr initcgr;
	u32 cs_th;
	int err;

	memset(&initcgr, 0, sizeof(struct qm_mcc_initcgr));
	memset(cgr, 0, sizeof(struct cgr_priv));
	err = qman_alloc_cgrid(&cgr->ingress_cgr.cgrid);
	if (err < 0) {
		pr_err("Error %d allocating CGR ID\n", err);
		goto out_error;
	}

	cgr->ingress_cgr.cb = cgr_cb;
	/* Enable CS TD, Congestion State Change Notifications. */
	initcgr.we_mask = QM_CGR_WE_CSCN_EN | QM_CGR_WE_CS_THRES | QM_CGR_WE_MODE;
	initcgr.cgr.cscn_en = QM_CGR_EN;
	initcgr.cgr.mode= 0; /*Byte mode*/
	cs_th = sec_congestion;

	qm_cgr_cs_thres_set64(&initcgr.cgr.cs_thres, cs_th, 1);
	printk("%s()::%d cs_th: %u mant %d exp %d\n", __func__, __LINE__,cs_th,
			initcgr.cgr.cs_thres.TA, initcgr.cgr.cs_thres.Tn);

	initcgr.we_mask |= QM_CGR_WE_CSTD_EN;
	initcgr.cgr.cstd_en = QM_CGR_EN;

	err = qman_create_cgr(&cgr->ingress_cgr, QMAN_CGR_FLAG_USE_INIT,
			&initcgr);
	if (err < 0) {
		pr_err("Error %d creating ingress CGR with ID %d\n", err,
				cgr->ingress_cgr.cgrid);
		qman_release_cgrid(cgr->ingress_cgr.cgrid);
		goto out_error;
	}
	pr_debug("Created ingress CGR %d\n", cgr->ingress_cgr.cgrid);

	/* cgr->use_ingress_cgr = true;*/

out_error:
	return err;
}

static void cdx_dpaa_ingress_cgr_exit(struct cgr_priv *cgr)
{
	int iRet = 0;

	if ((iRet = qman_delete_cgr(&cgr->ingress_cgr)))
		printk("Deletion of CGR failed: %d\n", iRet);
	else
		qman_release_cgrid(cgr->ingress_cgr.cgrid);

	return;
}
#endif


int cdx_dpa_ipsec_init(void)
{

	DPAIPSEC_INFO("%s::\n", __FUNCTION__);
	ipsecinfo.crypto_channel_id = qm_channel_caam;
	ipsecinfo.ipsec_exception_fq = NULL;
	if (ipsec_init_ohport(&ipsecinfo)) {
		return FAILURE;
	}
	if (add_ipsec_bpool(&ipsecinfo)) {
		return FAILURE;
	}
#ifdef CS_TAIL_DROP
	if (sec_congestion){
		if (cdx_dpaa_ingress_cgr_init(&ipsecinfo.cgr)) {
			return FAILURE;
		}
	}
#endif
	if (create_ipsec_pcd_fqs(&ipsecinfo, 1)) {
		goto ipsec_pcd_fq_failure;
	}
	dpa_ipsec_test(&ipsecinfo);
	register_cdx_deinit_func(cdx_dpa_ipsec_exit);
	return SUCCESS;

ipsec_pcd_fq_failure:
#ifdef CS_TAIL_DROP
	if(sec_congestion)
		cdx_dpaa_ingress_cgr_exit(&ipsecinfo.cgr);
#endif
	return FAILURE;
}

void cdx_dpa_ipsec_exit(void)
{
	DPAIPSEC_INFO("%s::\n", __FUNCTION__);
#ifdef CS_TAIL_DROP
	if(sec_congestion)
		cdx_dpaa_ingress_cgr_exit(&ipsecinfo.cgr);
#endif
	release_ipsec_bpool(&ipsecinfo);
	return;
}
#else
#define cdx_dpa_ipsec_init()
struct dpa_bp* get_ipsec_bp(void)
{
	return NULL;
}
#endif


