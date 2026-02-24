/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
        
/**     
 * @file                cdx_reassem.c     
 * @description         cdx DPAA ip reassembly with EHASH
 */             
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include "linux/netdevice.h"
#include "portdefs.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "misc.h"
#include "types.h"
#include "cdx.h"
#include "cdx_common.h"
#include "list.h"
#include "cdx_ioctl.h"
#include "layer2.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_ipsec.h"
#include "control_tunnel.h"
#include "control_bridge.h"
#include "fm_ehash.h"
#include "dpa_control_mc.h"
#include "control_pppoe.h"
#include "control_socket.h"
#include "module_rtp_relay.h"

//#define CDX_IPR_DEBUG 1

#ifdef CDX_IPR_DEBUG
#define CDX_IPR_DPRINT(fmt, args...) printk("%s:: " fmt, __func__, ##args)
#else
#define CDX_IPR_DPRINT(fmt, args...) do { } while(0)
#endif

//ip reassembly structure used between cmm and cdx
struct ipr_statistics {
	uint16_t ackstats; //mandated by fci/cmm
	struct ip_reassembly_info info;
};


//pool info for reassembly context pool
static struct port_bman_pool_info reassly_ctx_parent_pool_info;
struct dpa_bp *reassly_bp;
//pool info for reassembly fragment pool
static struct port_bman_pool_info reassly_frag_parent_pool_info;
struct dpa_bp *ipr_frag_bp;
//reassmebly timer tick task
static struct task_struct *ipr_timer_thread;


//IP reassembly timer frequency
#define IPR_TIMER_FREQUENCY   10      /* ticks per second */
#define IPR_TIMER_PERIOD    (HZ / IPR_TIMER_FREQUENCY) /* period, in jiffies */

/* external references */
/* extern void ipr_update_timestamp(void); */
/* reassembly config info */
extern struct cdx_ipr_info ipr_info;

static uint32_t cdx_reassem_txc;

struct ip_reassembly_frag_list {
	uint8_t ref_count; //valid on first entry only
	uint8_t num_entries; //valid on first entry only
	uint16_t bpid; //bpid for thie buffer
	uint32_t addr_lo;//DDR address lower 32 bits
	uint8_t addr_hi; //DDR address upper 8 bits
	uint8_t reserved[7];
}__attribute__ ((packed));

static inline struct dpa_bp *ipr_bpid2pool(uint32_t bpid)
{
#ifdef CDX_IPR_DEBUG
	CDX_IPR_DPRINT("%s:;bpid %d, reass %d, frag %d\n",
			__FUNCTION__, bpid, reassly_bp->bpid,
			ipr_frag_bp->bpid);
#endif
	if (bpid == reassly_bp->bpid)
		return reassly_bp;
	if (bpid == ipr_frag_bp->bpid)
		return ipr_frag_bp;
	return NULL;
} 

enum qman_cb_dqrr_result __hot ipr_buff_release_dqrr(
		struct qman_portal         *portal,
		struct qman_fq                  *fq,
		const struct qm_dqrr_entry      *dq)
{
	uint32_t ii;
	dma_addr_t addr;
	struct qm_sg_entry *sgt;
	uint8_t final;
	uint32_t offset;
	uint32_t num_entries;
	struct ip_reassembly_frag_list *list;	
	char *bufstart;

	cdx_reassem_txc++;
	addr = qm_fd_addr(&dq->fd);
	offset = dpa_fd_offset(&dq->fd);
	dma_sync_single_for_cpu(reassly_bp->dev, addr, reassly_bp->size, DMA_BIDIRECTIONAL);
	bufstart = (char *)phys_to_virt(addr);
#ifdef CDX_IPR_DEBUG	
	CDX_IPR_DPRINT("%s::\n", __FUNCTION__);
	CDX_IPR_DPRINT("fqid %x(%d) bpid %d addr %x:%08x status %08x offset %d addr %llx\n",
			dq->fqid, dq->fqid, dq->fd.bpid,
			dq->fd.addr_hi, dq->fd.addr_lo, dq->fd.status, offset, 
			addr);
#endif
	sgt = (struct qm_sg_entry *)(bufstart + offset);
	for (ii = 0; ii < 16; ii++) {
		final = qm_sg_entry_get_final(sgt);
#ifdef CDX_IPR_DEBUG	
		CDX_IPR_DPRINT("entry %d::", ii);
		display_buff_data((uint8_t *)sgt, sizeof(struct qm_sg_entry));
		addr = qm_sg_addr(sgt);
		CDX_IPR_DPRINT("sgt %p, addr %llx, final %d\n",
				sgt, addr, final);
#endif
		if (final)
			break;
		sgt++;
	}
	list = (struct ip_reassembly_frag_list *)bufstart;
	num_entries = list->num_entries;
#ifdef CDX_IPR_DEBUG	
	CDX_IPR_DPRINT("list %llx, refcount %d, entries %d\n",
			addr, list->ref_count, num_entries);
	for (ii = 0; ii < num_entries; ii++)
	{	
		uint32_t bpid;
		display_buff_data((uint8_t *)(list + ii), 
				sizeof(struct ip_reassembly_frag_list));
		addr = (list + ii)->addr_hi;
		addr <<= 32;
		addr |= cpu_to_be32((list + ii)->addr_lo); 
		bpid = cpu_to_be16((list + ii)->bpid);
		CDX_IPR_DPRINT("addr %llx, bpid %d\n", addr, bpid);
	}	
#endif
	list->ref_count--;
#ifdef CDX_IPR_DEBUG	
	CDX_IPR_DPRINT("refcount %d\n",
			list->ref_count);
#endif
	dma_sync_single_for_device(reassly_bp->dev, addr, reassly_bp->size, DMA_BIDIRECTIONAL);
	if (!list->ref_count)
	{
		for (ii = 0; ii < num_entries; ii++) {
			struct dpa_bp *bp;
			struct bm_buffer buf;
			buf.bpid = cpu_to_be16(list->bpid);
			bp = ipr_bpid2pool(buf.bpid);
			if (bp) {
				buf.hi = list->addr_hi;
				buf.lo = cpu_to_be32(list->addr_lo);
				//free members to pool
#ifdef CDX_IPR_DEBUG	
				CDX_IPR_DPRINT("releasing addr %x%08x to bpid %d "
						"bp %p\n",
						buf.hi, buf.lo, buf.bpid, bp);
#endif
				if (bman_release(bp->pool, &buf, 1, 0)) {
					DPA_ERROR("%s::bman release failed\n", 
							__FUNCTION__);
				}
			} else {
				DPA_ERROR("%s::unable to get bp for id %d\n", 
						__FUNCTION__, buf.bpid);
			}
			list++;
		}
	}
	return qman_cb_dqrr_consume;
}


int cdx_create_ipr_fq(uint32_t *base_fqid)
{
	uint32_t ii;
	struct dpa_fq *dpa_fq;
	uint32_t fqid;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals;
	uint32_t next_portal_ch_idx;
	const cpumask_t *affine_cpus;
	uint32_t fqid_base;

	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}
	if (!num_portals) {
		DPA_ERROR("%s::unable to get affined portal info\n",
				__FUNCTION__);
		return -1;
	}
#ifdef DEVMAN_DEBUG
	CDX_IPR_DPRINT("%s::num_portals %d ::", __FUNCTION__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		CDX_IPR_DPRINT("%d ", portal_channel[ii]);
	CDX_IPR_DPRINT("\n");
#endif
	if (qman_alloc_fqid_range(&fqid_base, num_portals, num_portals, 0) 
			!= num_portals) {
		DPA_ERROR("%s::unable to get ipr fqids\n",
				__FUNCTION__);
		return -1;
	}
#ifdef DEVMAN_DEBUG
	CDX_IPR_DPRINT("%s::fqid_base %x(%d), num %d\n",
			__FUNCTION__, fqid_base, fqid_base, num_portals);
#endif
	//create fqs
	fqid = fqid_base;
	for (ii = 0; ii < num_portals; ii++) {
		if (find_pcd_fq_info(fqid)) {
			dpa_fq = kzalloc(sizeof(struct dpa_fq), 0);
			if (!dpa_fq) {
				DPA_ERROR("%s::unable to alloc mem for "
						"fqid %d\n", __FUNCTION__, fqid);
				return -1;
			}
			memset(dpa_fq, 0, sizeof(struct dpa_fq));
			dpa_fq->fqid = fqid;
			dpa_fq->fq_type = FQ_TYPE_RX_PCD;
			//round robin channel ids
			dpa_fq->channel = portal_channel[next_portal_ch_idx];
			if (next_portal_ch_idx == (num_portals - 1))
				next_portal_ch_idx = 0;
			else
				next_portal_ch_idx++;
			//use ipr release callback 
			dpa_fq->fq_base.cb.dqrr = ipr_buff_release_dqrr;
			//create PCD FQ
			if (cdx_create_fq(dpa_fq, 0, NULL)) {
				DPA_ERROR("%s::cdx_create_fq failed for "
						"fqid %d\n", __FUNCTION__, fqid);
				kfree(dpa_fq);
				return -1;
			}
			add_pcd_fq_info(dpa_fq);
#ifdef DEVMAN_DEBUG
			CDX_IPR_DPRINT("%s::fqid 0x%x created chnl 0x%x\n", 
					__FUNCTION__, fqid, dpa_fq->channel);
#endif
		} 
#ifdef DEVMAN_DEBUG
		else {
			CDX_IPR_DPRINT("%s::fqid 0x%x already created\n", 
					__FUNCTION__, fqid);
		}
#endif
		fqid++;
	}
	*base_fqid = fqid_base; 
	return num_portals;
}

static inline int fill_ipr_bpool(struct dpa_bp *bp, struct dpa_bp *bp_parent, uint32_t count)
{
	uint32_t buffer_count;

	buffer_count = 0;
	while (buffer_count < count)
	{
		struct bm_buffer buf;

		memset(&buf, 0, sizeof(struct bm_buffer));
		if (bman_acquire(bp_parent->pool, &buf, 1, 0) != 1) 
			break;
#ifdef CDX_IPR_DEBUG
		CDX_IPR_DPRINT("%s::moving buffer %p to pool %d\n",
				__FUNCTION__, (void *)(uint64_t)(buf.addr), bp->bpid);
#endif
		if (bman_release(bp->pool, &buf, 1, 0)) {
			DPA_ERROR("%s::bman release failed\n", __FUNCTION__);
			break;
		}
		buffer_count++;
	}
	return (buffer_count);
}

static inline struct dpa_bp *create_ipr_bpool(uint32_t size, uint32_t count, 	
		struct dpa_bp *bp_parent)
{
	struct dpa_bp *bp;
	uint32_t buffer_count;

	bp = kzalloc(sizeof(struct dpa_bp), 0);
	if (unlikely(bp == NULL)) {
		DPA_ERROR("%s::failed to allocate mem for bman pool for reassly\n", 
				__FUNCTION__);
		return NULL;
	}
	bp->dev = bp_parent->dev;
	bp->size = size;
	if (!count)
		bp->config_count = 0xffff; 
	//just fill some number to make dpa_bp_alloc pass
	else
		bp->config_count = count;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPA_ERROR("%s::dpa_bp_alloc failed for reassly\n", 
				__FUNCTION__);
		kfree(bp);
		return NULL;
	}
	CDX_IPR_DPRINT("%s::allocated pool %d bp->size :%zu\n", __FUNCTION__, bp->bpid, bp->size);
	printk("%s::allocated pool %d bp->size :%zu\n", __FUNCTION__, bp->bpid, bp->size);
	if (count) {
		buffer_count = fill_ipr_bpool(bp, bp_parent, count);
		if (buffer_count) {
			CDX_IPR_DPRINT("%s::%d buffers added to pool %d\n",
					__FUNCTION__, buffer_count, bp->bpid);
			printk("%s::%d buffers added to pool %d\n",
					__FUNCTION__, buffer_count, bp->bpid);
		} else {
			CDX_IPR_DPRINT("%s::no buffers added to pool %d\n",
					__FUNCTION__, bp->bpid);
		}
	}
	return bp;
}

//hook function to replenish ipr fragment buffer pool
static int replenish_ipr_frag_pool(struct net_device *net_dev, u32 bpid)
{
	struct dpa_bp *bp;
	struct dpa_bp *bp_parent;

	bp_parent = dpa_bpid2pool(reassly_frag_parent_pool_info.pool_id);
	if (bpid == ipr_frag_bp->bpid) {
		//replenish one buffer
		bp = dpa_bpid2pool(bpid);
		if (fill_ipr_bpool(bp, bp_parent, 1) != 1) {
			DPA_ERROR("%s::No buffers replenished to pool %d\n!!!!!\n",
					__FUNCTION__, bpid);
			return -1;
		}
	}
	return 0;
}

int ipr_timer(void *data)
{
	while (!kthread_should_stop())
	{
		msleep(1000 / IPR_TIMER_FREQUENCY);
		ipr_update_timestamp();
	}
	return 0;
}

static void cdx_deinit_ip_reassembly(void)
{
	printk("%s::implement this\n", __FUNCTION__);
	return;
}

int cdx_init_ip_reassembly(void)
{
	struct dpa_bp *bp_parent;
	uint32_t fqid; 
	int num_fqs;

	printk("%s::\n", __FUNCTION__);
	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(ipr_info.ipr_ctx_bsize, 
				&reassly_ctx_parent_pool_info)) {
		DPA_ERROR("%s::failed to locate eth bman pool for reassly\n", 
				__FUNCTION__);
		return -1;
	}
	bp_parent = dpa_bpid2pool(reassly_ctx_parent_pool_info.pool_id);
	CDX_IPR_DPRINT("%s::parent bman pool for reassly - bp %p, bpid %d paddr %lx vaddr %p dev %p\n", 
			__FUNCTION__, bp_parent, reassly_ctx_parent_pool_info.pool_id,
			(unsigned long)bp_parent->paddr, bp_parent->vaddr, bp_parent->dev);

	reassly_bp = create_ipr_bpool(ipr_info.ipr_ctx_bsize, 
			ipr_info.max_contexts, 
			bp_parent);
	if (!reassly_bp) {
		DPA_ERROR("%s::failed to create pool for reassly context\n", 
				__FUNCTION__);
		return -1;
	}
	//create thread for updating ip reassembly time stamp location
	ipr_timer_thread = kthread_run(ipr_timer, &ipr_timer_thread, "ipr_timer");
	if (IS_ERR(ipr_timer_thread))
	{
		DPA_ERROR(KERN_ERR "%s: kthread_create() failed\n", __func__);
		return -1;
	}
	CDX_IPR_DPRINT("%s::created ipr timer thread %p\n", __FUNCTION__,
			ipr_timer_thread);
	CDX_IPR_DPRINT("%s::context pool %d bp->size :%zu\n", __FUNCTION__, 
			reassly_bp->bpid, reassly_bp->size);

	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(ipr_info.ipr_frag_bsize, 
				&reassly_frag_parent_pool_info)) {
		DPA_ERROR("%s::failed to locate eth bman pool for frag buffs\n", 
				__FUNCTION__);
		return -1;
	}
	bp_parent = dpa_bpid2pool(reassly_frag_parent_pool_info.pool_id);
	CDX_IPR_DPRINT("%s::parent bman pool for reassly - bp %p, bpid %d paddr %lx vaddr %p dev %p\n", 
			__FUNCTION__, bp_parent, reassly_frag_parent_pool_info.pool_id,
			(unsigned long)bp_parent->paddr, bp_parent->vaddr, bp_parent->dev);

	ipr_frag_bp = create_ipr_bpool(ipr_info.ipr_frag_bsize, 
			(ipr_info.max_contexts * ipr_info.max_frags), 
			bp_parent);
	if (!ipr_frag_bp) {
		DPA_ERROR("%s::failed to create pool for ipr fragments\n", 
				__FUNCTION__);
		return -1;
	}
	num_fqs = cdx_create_ipr_fq(&fqid);
	if (num_fqs == -1) {
		DPA_ERROR("%s::unable to create txconf fqids for IPV4_REASSM\n", 
				__FUNCTION__);
		return -1;
	}
	CDX_IPR_DPRINT("%s::ipr txconf fqbase %x(%d), num fqs %d\n",
			__FUNCTION__, fqid, fqid, num_fqs);
	//push num fqs into upper bytes of the fields
	fqid |= (num_fqs << 24);
	if (ExternalHashSetReasslyPool(IPV4_REASSM_TABLE, reassly_bp->bpid, 
				reassly_bp->size,
				ipr_frag_bp->bpid, 
				ipr_frag_bp->size, 
				fqid,
				IPR_TIMER_FREQUENCY)) {
		DPA_ERROR("%s::unable to set bpid for IPV4_REASSM_TABLE\n", 
				__FUNCTION__);
		return -1;
	}	
	if (ExternalHashSetReasslyPool(IPV6_REASSM_TABLE , 
				reassly_bp->bpid, 
				reassly_bp->size, 
				ipr_frag_bp->bpid, 
				ipr_frag_bp->size, 
				fqid,
				IPR_TIMER_FREQUENCY)) {
		DPA_ERROR("%s::unable to set bpid for IPV4_REASSM_TABLE\n", 
				__FUNCTION__);
		return -1;
	}
	//register hook to replenish frag buffer pool
	register_dpaa_eth_bpool_replenish_hook(replenish_ipr_frag_pool);	
	register_cdx_deinit_func(cdx_deinit_ip_reassembly);
	return 0;
}

int cdx_get_ipr_v4_stats(void *resp)
{
	struct ipr_statistics *ipr_stats;

	printk("%s:cdx_reassem_txc %d\n", __FUNCTION__, cdx_reassem_txc);
	ipr_stats = (struct ipr_statistics *)resp;
	if (get_ip_reassem_info(IPV4_REASSM_TABLE, &ipr_stats->info))
		return -1;	
	return (sizeof(struct ipr_statistics));
}
int cdx_get_ipr_v6_stats(void *resp)
{
	struct ipr_statistics *ipr_stats;

	printk("%s:cdx_reassem_txc %d\n", __FUNCTION__, cdx_reassem_txc);
	ipr_stats = (struct ipr_statistics *)resp;
	if (get_ip_reassem_info(IPV6_REASSM_TABLE, &ipr_stats->info))
		return -1;	
	return (sizeof(struct ipr_statistics));
}

