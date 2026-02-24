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

#include <linux/fsl_bman.h>

#if defined (CONFIG_VWD_MULTI_MAC)
#include "br_private.h"
#endif

#include "portdefs.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "dpa_wifi.h"
#include "layer2.h"
#include "cdx.h"
#include "procfs.h"

#ifdef DPA_WIFI_DEBUG
static char disp_data[1024];
#endif

/* Enable UNIT_TEST to test for cellular */
/*#define UNIT_TEST 1 */
//uncomment to allow debug prints
//#define DPA_WIFI_DEBUG  1

static unsigned int num_tx_sent = 0;
static DEFINE_PER_CPU(unsigned int, num_tx_done);
#define PORTID_SHIFT_VAL 	8
#define VAP_SG_BUF_COUNT	128	
#define VAP_SG_BUF_HEAD_ROOM	128	
#define MAX_HEAD_ROOM_LEN	512
#define DPAWIFI_ERROR(fmt, ...)\
{\
        printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#define DPAWIFI_INFO(fmt, ...)\
{\
        printk(KERN_INFO fmt, ## __VA_ARGS__);\
}

#define percpu_var_sum(var, total)\
{\
	unsigned int ii; \
	total = 0;\
	for_each_possible_cpu(ii)\
		total += per_cpu(var, ii);\
}

#define INCR_PER_CPU_STAT(ptr, stat)\
{\
        get_cpu_ptr((ptr))->stat++;\
        put_cpu_ptr((ptr));\
}

#ifdef CFG_WIFI_OFFLOAD

struct dpaa_vwd_priv_s vwd;
unsigned int vwd_ofld = VWD_BHR_MODE;

extern struct dpa_bp *dpa_bpid2pool(int bpid);
extern struct dpa_priv_s* get_eth_priv(unsigned char* name);

static int dpaa_vwd_open(struct inode *inode, struct file *file);
static int dpaa_vwd_close(struct inode * inode, struct file * file);
static long dpaa_vwd_ioctl(struct file * file, unsigned int cmd, unsigned long arg);

// nf_hookfn modified in netfilter.h //const struct nf_hook_ops *ops,
static unsigned int dpaa_vwd_nf_route_hook_fn( void *ops,struct sk_buff *skb,const struct nf_hook_state *state);
static unsigned int dpaa_vwd_nf_bridge_hook_fn( void *ops,struct sk_buff *skb,const struct nf_hook_state *state);

static int dpaa_vwd_send_packet(struct dpaa_vwd_priv_s *priv, void *vap_handle, struct sk_buff *skb);
static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_show_vap_stats(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_show_fast_path_enable(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_set_fast_path_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
static ssize_t vwd_show_oh_buff_limit(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_set_oh_buff_limit(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
static DEVICE_ATTR(vwd_debug_stats, 0444, vwd_show_dump_stats, NULL);
static DEVICE_ATTR(vwd_fast_path_enable, 0644, vwd_show_fast_path_enable, vwd_set_fast_path_enable);
static struct device_attribute dev_attr_vap[MAX_WIFI_VAPS];
static DEVICE_ATTR(vwd_oh_buff_limit, 0644, vwd_show_oh_buff_limit, vwd_set_oh_buff_limit);
static int process_vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq, const struct qm_dqrr_entry *dq);
void drain_bp_tx_done_bpool(struct dpa_bp *bp);

static int (*vwd_rx_hdlr)(struct sk_buff *);

static unsigned int oh_buff_limit = 1024;

static int wifi_rx_dummy_hdlr(struct sk_buff *skb)
{
	return -1;
}

int wifi_rx_fastpath_register(int (*hdlr)(struct sk_buff *skb))
{
	pr_info("%s:%d VWD Tx function registered\n", __func__, __LINE__ );
	vwd_rx_hdlr = hdlr;

	return 0;
}

void wifi_rx_fastpath_unregister(void)
{
	pr_info("%s:%d VWD Tx function unregistered\n", __func__, __LINE__ );
	vwd_rx_hdlr = wifi_rx_dummy_hdlr;

	return;
}

int cdx_wifi_rx_fastpath(struct sk_buff *skb)
{
	return vwd_rx_hdlr(skb);

}
EXPORT_SYMBOL(cdx_wifi_rx_fastpath);

static const struct file_operations vwd_fops = {
	.owner                  = THIS_MODULE,
	.open                   = dpaa_vwd_open,
	.unlocked_ioctl         = dpaa_vwd_ioctl,
	.release                = dpaa_vwd_close
};

/* IPV4 route hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook = {
	.hook = dpaa_vwd_nf_route_hook_fn,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

/* IPV6 route hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook_ipv6 = {
	.hook = dpaa_vwd_nf_route_hook_fn,
	.pf = PF_INET6,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP6_PRI_FIRST,
};

/* Bridge hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook_bridge = {
	.hook = dpaa_vwd_nf_bridge_hook_fn,
	.pf = PF_BRIDGE,
	.hooknum = NF_BR_PRE_ROUTING,
	.priority = NF_BR_PRI_FIRST,
};



#define DPA_WRITE_NETDEV_PTR(dev, devh, addr, off) \
{ \
	devh = (struct net_device **)addr; \
	*(devh + (off)) = dev; \
}
#define DPA_READ_NETDEV_PTR(dev, devh, addr, off) \
{ \
	devh = (struct net_device **)addr; \
	dev = *(devh + (off)); \
}
#ifdef UNIT_TEST
unsigned char temp_ethhdr[16];
#endif

/* In case VWD OFFLOAD , headers can be added in ucode, and the length of the 
	 original buffer can be increased. And this increased length is written from 
	 fixed offset (192) for packets coming from OH port causing headers to grow at tail.
	 So tailroom is introduced to allow the tail to grow upto 64 bytes */
#define SKB_ASK_TAILROOM 	64

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,3)
bool a050385_check_skb(struct sk_buff *skb, struct dpa_priv_s *priv);
struct sk_buff *a050385_realign_skb(struct sk_buff *skb, struct dpa_priv_s *priv);
#else

/* Realign the skb by copying its contents at the start of a newly allocated
 * page. Build a new skb around the new buffer and release the old one.
 * A performance drop should be expected.
 */
static struct sk_buff *a010022_realign_skb(struct sk_buff *skb,
		struct dpa_priv_s *priv)
{
	int trans_offset = skb_transport_offset(skb);
	int net_offset = skb_network_offset(skb);
	struct sk_buff *nskb = NULL;
	int nsize, headroom;
	struct page *npage;
	void *npage_addr;

	/* Guarantee the minimum required headroom */
	headroom = priv->tx_headroom;

	npage = alloc_page(GFP_ATOMIC);
	if (unlikely(!npage)) {
		WARN_ONCE(1, "Memory allocation failure\n");
		return NULL;
	}
	npage_addr = page_address(npage);

	/* For the new skb we only need the old one's data (both non-paged and
	 * paged) and a headroom large enough to fit our private info. We can
	 * skip the old tailroom.
	 *
	 * Make sure the new linearized buffer will not exceed a page's size.
	 */
	/* A new tailroom is introduced as there is a scope of growth of packet
		 at tail when ucode adds headers to the original buffer */
	nsize = SKB_DATA_ALIGN(skb->len + headroom + SKB_ASK_TAILROOM ) +
		SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	if (unlikely(nsize > 4096))
		goto err;

	nskb = build_skb(npage_addr, nsize);
	if (unlikely(!nskb))
		goto err;

	/* Reserve only the needed headroom in order to guarantee the data's
	 * alignment.
	 * Code borrowed and adapted from skb_copy().
	 */
	skb_reserve(nskb, headroom);
	skb_put(nskb, skb->len);
	if (skb_copy_bits(skb, 0, nskb->data, skb->len)) {
		WARN_ONCE(1, "skb parsing failure\n");
		goto err;
	}
	copy_skb_header(nskb, skb);

#ifdef CONFIG_FSL_DPAA_TS
	/* Copy relevant timestamp info from the old skb to the new */
	if (priv->ts_tx_en) {
		skb_shinfo(nskb)->tx_flags = skb_shinfo(skb)->tx_flags;
		skb_shinfo(nskb)->hwtstamps = skb_shinfo(skb)->hwtstamps;
		skb_shinfo(nskb)->tskey = skb_shinfo(skb)->tskey;
		if (skb->sk)
			skb_set_owner_w(nskb, skb->sk);
	}
#endif
	/* We move the headroom when we align it so we have to reset the
	 * network and transport header offsets relative to the new data
	 * pointer. The checksum offload relies on these offsets.
	 */
	skb_set_network_header(nskb, net_offset);
	skb_set_transport_header(nskb, trans_offset);

	/* We don't want the buffer to be recycled so we mark it accordingly */
	nskb->mark = NONREC_MARK;

	dev_kfree_skb(skb);
	return nskb;

err:
	if (nskb)
		dev_kfree_skb(nskb);
	put_page(npage);
	return NULL;
}

/* Verify the conditions that trigger the A010022 errata: data unaligned to
 * 16 bytes and 4K memory address crossings.
 */
static bool a010022_check_skb(struct sk_buff *skb, struct dpa_priv_s *priv)
{
	int nr_frags, i = 0;
	skb_frag_t *frag;
	/* Check if the headroom is aligned */
	if (((uintptr_t)skb->data - priv->tx_headroom) %
			priv->buf_layout[TX].data_align != 0) {
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:%d %p : %x : %x \n", __func__, __LINE__, skb->data, priv->tx_headroom, priv->buf_layout[TX].data_align);
#endif
		return true;
	}

	/* Check if the headroom crosses a boundary */
	if (HAS_DMA_ISSUE(skb->head, skb_headroom(skb))) {
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:%d\n", __func__, __LINE__);
#endif
		return true;
	}

	/* Check if the non-paged data crosses a boundary */
	if (HAS_DMA_ISSUE(skb->data, skb_headlen(skb))) {
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:%d\n", __func__, __LINE__);
#endif
		return true;
	}

	/* Check if the entire linear skb crosses a boundary */
	if (HAS_DMA_ISSUE(skb->head, skb_end_offset(skb))) {
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:%d\n", __func__, __LINE__);
#endif
		return true;
	}

	nr_frags = skb_shinfo(skb)->nr_frags;

	while (i < nr_frags) {
		frag = &skb_shinfo(skb)->frags[i];

		/* Check if a paged fragment crosses a boundary from its
		 * offset to its end.
		 */
		if (HAS_DMA_ISSUE(frag->page_offset, frag->size)) {
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_INFO("%s:%d\n", __func__, __LINE__);
#endif
			return true;
		}

		i++;
	}

	return false;
}
#endif

/* This function will return 1 if the device is cellular (i.e no_l2_itf) */
int vwd_is_no_l2_itf_device(struct net_device* dev)
{
	struct vap_desc_s *vap;
	if (dev->wifi_offload_dev)
	{
		vap = (struct vap_desc_s *)dev->wifi_offload_dev;
		if (vap->no_l2_itf)
			return 1;
	}
	return 0;
}

/* This function transmits local ESP packets to SEC for processing */
static int vwd_xmit_local_packet(struct sk_buff *skb)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct vap_desc_s *vap;
	unsigned char hdroom_realloced = 0;
	int ret;

	INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_total_local_tx);
	if (!skb->dev->wifi_offload_dev)
		goto send_pkt;

	vap = (struct vap_desc_s *)skb->dev->wifi_offload_dev;

	if (vap->no_l2_itf)
	{
#ifdef UNIT_TEST
		{
			printk("%s:: Removing ethernet header: %d\n", __func__,skb->mac_len);
			memcpy(temp_ethhdr, skb->data, 12);
			skb_pull(skb, ETH_HLEN);
			/*skb_reset_network_header(skb);*/
			skb->mac_len = 0;
		}
#endif
		ret = dpa_add_dummy_eth_hdr(&skb, 0, &hdroom_realloced); 

		if (ret < 0)
			goto send_pkt;

		skb_push(skb, ETH_HLEN);
#ifdef UNIT_TEST
		memcpy(skb->data,temp_ethhdr,12);
#endif

		if (hdroom_realloced) {
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_no_head);
		}
	}

	INCR_PER_CPU_STAT(vap->vap_stats, pkts_local_tx_dpaa);
	dpaa_submit_outb_pkt_to_SEC(skb, skb->dev, priv->txconf_bp);

	return 0;
send_pkt:
	return original_dev_queue_xmit(skb);
}

static ssize_t vwd_show_vap_stats(struct device *dev, struct device_attribute *attribute, char *buf)
{
	ssize_t len = 0;
	struct dpaa_vwd_priv_s *priv = &vwd;
	int ii = 0;

	struct vap_stats_s *per_cpu_stats;
	struct vap_stats_s total_stats;
	int i;

	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		if (!strcmp(attribute->attr.name, priv->vaps[ii].ifname)) {
			break;
		}
	}

	/* No vap entry */
	if (ii == MAX_WIFI_VAPS)
		return 0;

	memset(&total_stats, 0, sizeof(struct vap_stats_s));
	for_each_possible_cpu(i) {
		per_cpu_stats = per_cpu_ptr(priv->vaps[ii].vap_stats, i);
		total_stats.pkts_local_tx_dpaa += per_cpu_stats->pkts_local_tx_dpaa;
		total_stats.pkts_transmitted += per_cpu_stats->pkts_transmitted;
		total_stats.pkts_slow_forwarded += per_cpu_stats->pkts_slow_forwarded;
		total_stats.pkts_tx_dropped += per_cpu_stats->pkts_tx_dropped;
		total_stats.pkts_rx_fast_forwarded += per_cpu_stats->pkts_rx_fast_forwarded;
		total_stats.pkts_tx_sg += per_cpu_stats->pkts_tx_sg;
		total_stats.pkts_tx_cloned += per_cpu_stats->pkts_tx_cloned;
		total_stats.pkts_tx_no_head += per_cpu_stats->pkts_tx_no_head;
		total_stats.pkts_tx_non_linear += per_cpu_stats->pkts_tx_non_linear;
		total_stats.pkts_tx_realign += per_cpu_stats->pkts_tx_realign;
		total_stats.pkts_tx_route += per_cpu_stats->pkts_tx_route;
		total_stats.pkts_tx_bridge += per_cpu_stats->pkts_tx_bridge;
		total_stats.pkts_direct_rx += per_cpu_stats->pkts_direct_rx;
		total_stats.pkts_rx_ipsec += per_cpu_stats->pkts_rx_ipsec;
		total_stats.pkts_oh_buf_threshold_drop += per_cpu_stats->pkts_oh_buf_threshold_drop;
		total_stats.pkts_slow_path_drop += per_cpu_stats->pkts_slow_path_drop;
	}

	len += sprintf(buf, "VAP (id : %d  name : %s)\n",ii,priv->vaps[ii].ifname);
	len += sprintf(buf + len, "\nTo DPAA\n");
	len += sprintf(buf + len, "  WiFi Rx pkts from route hook : %u\n", total_stats.pkts_tx_route);
	len += sprintf(buf + len, "  WiFi Rx pkts from bridge hook : %u\n", total_stats.pkts_tx_bridge);
	len += sprintf(buf + len, "  WiFi Rx pkts from direct rx : %u\n", total_stats.pkts_direct_rx);
	len += sprintf(buf + len, "  WiFi Rx pkts submitted to DPAA : %u\n", total_stats.pkts_transmitted);
	len += sprintf(buf + len, "  WiFi local Tx pkts submitted to DPAA : %u\n", total_stats.pkts_local_tx_dpaa);
	len += sprintf(buf + len, "  Drops while sending it to DPAA : %u\n", total_stats.pkts_tx_dropped);
	len += sprintf(buf + len, "  WiFI OH buf threshold Drops : %u\n", total_stats.pkts_oh_buf_threshold_drop);
	len += sprintf(buf + len, "  SG packets|No head room|non linear|cloned|realign - %x : %x : %x : %x : %x\n", total_stats.pkts_tx_sg, total_stats.pkts_tx_no_head, total_stats.pkts_tx_non_linear, total_stats.pkts_tx_cloned, total_stats.pkts_tx_realign);

	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  WiFi Rx pkts : %u \n", total_stats.pkts_slow_forwarded);
	len += sprintf(buf + len, "  WiFi Tx pkts : %u \n", total_stats.pkts_rx_fast_forwarded);
	len += sprintf(buf + len, "  WiFi Tx ipsec pkts : %u\n", total_stats.pkts_rx_ipsec);
	len += sprintf(buf + len, "  WiFI Rx slow path drops : %u\n", total_stats.pkts_slow_path_drop);

	return len;
}

/** vwd_show_dump_stats
 *
 */
static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	struct dpaa_vwd_priv_s *priv = &vwd;
	unsigned int total_num_tx_done;
	//int ii;
	struct vwd_global_stats_s *per_cpu_stats;
	struct vwd_global_stats_s total_stats;
	int i;

	memset(&total_stats, 0, sizeof(struct vwd_global_stats_s));
	for_each_possible_cpu(i) {
		per_cpu_stats = per_cpu_ptr(priv->vwd_global_stats, i);
		total_stats.pkts_total_local_tx += per_cpu_stats->pkts_total_local_tx;
		total_stats.pkts_slow_fail += per_cpu_stats->pkts_slow_fail;
		total_stats.pkts_dev_down_drop += per_cpu_stats->pkts_dev_down_drop;
	}

	len += sprintf(buf + len, "\nStatus\n");
	len += sprintf(buf + len, "  Fast path - %s\n", priv->fast_path_enable ? "Enable" : "Disable");
	percpu_var_sum(num_tx_done, total_num_tx_done);
	len += sprintf(buf + len, "  tx_sent:done  %u:%u\n", num_tx_sent, total_num_tx_done);

	len += sprintf(buf + len, "\nTo DPAA\n");
	len += sprintf(buf + len, "  WiFi local Tx pkts : %u\n", total_stats.pkts_total_local_tx);

	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  WiFI Rx Fails : %u\n", total_stats.pkts_slow_fail);
	len += sprintf(buf + len, "  WiFI Device Down Drops : %u\n", total_stats.pkts_dev_down_drop);

#if 0
	len += sprintf(buf + len, "VAPs Configuration  : \n");
	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		struct vap_desc_s *vap;

		vap = &priv->vaps[ii];

		if (vap->state == VAP_ST_CLOSE)
			continue;

		len += sprintf(buf + len, "VAP Name : %s \n", vap->ifname);
		len += sprintf(buf + len, "     Id             : %d \n", vap->vapid);
		len += sprintf(buf + len, "     Index          : %d \n", vap->ifindex);
		len += sprintf(buf + len, "     State          : %s \n", (vap->state  == VAP_ST_OPEN) ? "OPEN":"CLOSED");
		len += sprintf(buf + len, "     CPU Affinity   : %d \n", vap->cpu_id);
		len += sprintf(buf + len, "     Direct Rx path : %s \n", vap->direct_rx_path ? "ON":"OFF");
		len += sprintf(buf + len, "     Direct Tx path : %s \n", vap->direct_tx_path ? "ON":"OFF");
		len += sprintf(buf + len, "     No L2 interface:%d\n",vap->no_l2_itf);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
		len += sprintf(buf + len, "     Dev features   : VAP: %llx WiFi: %llx \n\n", vap->dev->features, vap->wifi_dev ? vap->wifi_dev->features:0);
#else
		len += sprintf(buf + len, "     Dev features   : VAP: %x WiFi: %x \n\n", vap->dev->features, vap->wifi_dev ? vap->wifi_dev->features:0);
#endif
	}
#endif
	return len;
}


/** vwd_show_fast_path_enable
 *
 */
static ssize_t vwd_show_fast_path_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int idx;

	idx = sprintf(buf, "\n%d\n", priv->fast_path_enable);
	return idx;
}

/** vwd_set_fast_path_enable
 *
 */
static ssize_t vwd_set_fast_path_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct dpaa_vwd_priv_s  *priv = &vwd;
	unsigned int fast_path = 0;

	sscanf(buf, "%d", &fast_path);
	if (fast_path && !priv->fast_path_enable)
	{
		DPAWIFI_INFO("%s: Wifi fast path enabled \n", __func__);
		priv->fast_path_enable = 1;
	}
	else if (!fast_path && priv->fast_path_enable)
	{
		DPAWIFI_INFO("%s: Wifi fast path disabled \n", __func__);
		priv->fast_path_enable = 0;
	}
	return count;
}

/** vwd_show_oh_buff_limit
 *
 */
static ssize_t vwd_show_oh_buff_limit(struct device *dev, struct device_attribute *attr, char *buf)
{
	int idx;

	idx = sprintf(buf, "\n%d\n", oh_buff_limit);
	return idx;
}

/** vwd_set_oh_buff_limit
 *
 */
static ssize_t vwd_set_oh_buff_limit(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int buff_limit = 0;

	sscanf(buf, "%d", &buff_limit);
	if (buff_limit <= 0)
	{
		DPAWIFI_INFO("%s: Invalid buff limit value \n", __func__);
	}
	oh_buff_limit = buff_limit;
	return count;
}


/** dpaa_vwd_sysfs_init
 *
 */
static int dpaa_vwd_sysfs_init( struct dpaa_vwd_priv_s *priv )
{

	if (device_create_file(priv->vwd_device, &dev_attr_vwd_debug_stats))
		goto err_dbg_sts;

	if (device_create_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable))
		goto err_fp_en;

#if 0
	if ((vwd_ofld == PFE_VWD_NAS_MODE ) && device_create_file(priv->vwd_device, &dev_attr_vwd_vap_create))
		goto err_vap_add;

	if ((vwd_ofld == PFE_VWD_NAS_MODE) && device_create_file(priv->vwd_device, &dev_attr_vwd_vap_reset))
		goto err_vap_del;

	if (device_create_file(vwd->vwd_device, &dev_attr_vwd_tso_stats))
		goto err_tso_stats;
#endif

#ifdef VWD_NAPI_STATS
	if (device_create_file(priv->vwd_device, &dev_attr_vwd_napi_stats))
		goto err_napi;
#endif

#ifdef VWD_LRO_STATS
	if (device_create_file(priv->vwd_device, &dev_attr_vwd_lro_nb_stats))
		goto err_lro_nb;

	if (device_create_file(priv->vwd_device, &dev_attr_vwd_lro_len_stats))
		goto err_lro_len;
#endif
	if (device_create_file(priv->vwd_device, &dev_attr_vwd_oh_buff_limit))
		goto err_oh_buff_limit;
	return 0;
err_oh_buff_limit:
#ifdef VWD_LRO_STATS
	device_remove_file(priv->vwd_device, &dev_attr_vwd_lro_len_stats);
err_lro_len:
	device_remove_file(priv->vwd_device, &dev_attr_vwd_lro_nb_stats);
err_lro_nb:
#endif

#ifdef VWD_NAPI_STATS
	device_remove_file(priv->vwd_device, &dev_attr_vwd_napi_stats);
err_napi:
#endif

#if defined(PFE_VWD_LRO_STATS) || defined(PFE_VWD_NAPI_STATS)
	device_remove_file(priv->vwd_device, &dev_attr_vwd_tso_stats);
#endif

#if 0
err_tso_stats:
	if (vwd_ofld == VWD_NAS_MODE)
		device_remove_file(priv->vwd_device, &dev_attr_vwd_vap_reset);
err_vap_del:
	if (vwd_ofld == VWD_NAS_MODE)
		device_remove_file(priv->vwd_device, &dev_attr_vwd_vap_create);
err_rt:
#endif
	device_remove_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable);
err_fp_en:
	device_remove_file(priv->vwd_device, &dev_attr_vwd_debug_stats);
err_dbg_sts:
	return -1;

}

/** dpaa_vwd_sysfs_exit
 *
 */
static void dpaa_vwd_sysfs_exit(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;

#if 0
	device_remove_file(priv->vwd_device, &dev_attr_vwd_tso_stats);
#ifdef PFE_VWD_LRO_STATS
	device_remove_file(priv->vwd_device, &dev_attr_vwd_lro_len_stats);
	device_remove_file(priv->vwd_device, &dev_attr_vwd_lro_nb_stats);
#endif
#endif

	device_remove_file(priv->vwd_device, &dev_attr_vwd_oh_buff_limit);
#ifdef PFE_VWD_NAPI_STATS
	device_remove_file(priv->vwd_device, &dev_attr_vwd_napi_stats);
#endif
#if 0
	if (vwd_ofld == PFE_VWD_NAS_MODE) {
		device_remove_file(priv->vwd_device, &dev_attr_vwd_vap_create);
		device_remove_file(priv->vwd_device, &dev_attr_vwd_vap_reset);
	}
#endif
	device_remove_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable);
	device_remove_file(priv->vwd_device, &dev_attr_vwd_debug_stats);
}

/* This function returns 1 if the packet is not supported
	 in fast path */
static int vwd_unsupported_eth_packet(struct sk_buff* skb)
{
	unsigned char* data_ptr;
	int length;
	/* Move to packet network header */
	data_ptr = skb_mac_header(skb);
	length = skb->len + (skb->data - data_ptr);
	/* Broadcasts and MC are handled by stack */
	if((eth_hdr(skb)->h_dest[0] & 0x1) || ( length <= ETH_HLEN ) )
	{
		return 1;
	}
	/* Jambo frames are not supported, will be handled by stack */
	if( length > ETH_FRAME_LEN )
	{
		DPAWIFI_INFO(KERN_INFO "%s:%d frame len:%d is bigger. Disable LRO/GRO on %s\n", __func__, __LINE__, length, skb->dev->name);
		return 1;
	}

	return 0;
}

/* This function returns 1 if the routed packet is not offloaded and sent to stack
	 and 0 for all packets sent to fast past , only routed packets are handled here*/
static int vwd_classify_route_packet( struct dpaa_vwd_priv_s *priv,struct sk_buff **skb_in, int *vapid)
{
	int rc = 1;	
	struct sk_buff *skb = *skb_in;
	struct vap_desc_s *vap;
	unsigned char hdroom_realloced = 0;

	spin_lock_bh(&priv->vaplock);
	/* getting vap structure from netdev pointer */
	vap = (struct vap_desc_s*)skb->dev->wifi_offload_dev;

	/* when a packet is received on other than wifi fastpath devices,
	 * vap can be NULL
	 */
	/* All bridge packets are handled in bridge hook  and bridge 
		 device should not have wifi_offloade_dev set*/
	if (!vap) 
		goto done;

	if (vap->ifindex != skb->skb_iif)
		goto done;

	/* packets sent to DPAA and returned from DPAA with no entry 
		 should be given to host */
	if (skb->expt_pkt == 1)
	{
		skb->expt_pkt = 0;
		goto done;
	}
	*vapid = vap->vapid;

	/* handle packets with NO L2 header */
	if (vap->no_l2_itf)
	{
		spin_unlock_bh(&priv->vaplock);
#ifdef UNIT_TEST
		memcpy(temp_ethhdr, (skb->data - ETH_HLEN), 12);
#endif
		if (dpa_add_dummy_eth_hdr(skb_in, priv->eth_priv->tx_headroom, &hdroom_realloced)  < 0 )
			return 1;

		skb = *skb_in;
#ifdef UNIT_TEST
		memcpy((skb->data - ETH_HLEN), temp_ethhdr, 12);
#endif

		if (hdroom_realloced) {
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_no_head);
		}
		return 0;
	}

	if (vwd_unsupported_eth_packet(skb))
		goto done;

	if (skb->protocol != ntohs(ETH_P_IP) && skb->protocol != ntohs(ETH_P_IPV6))
		goto done;

	rc = 0; /* Success */
done:
	spin_unlock_bh(&priv->vaplock);
	return rc;
}

/* This fucntion returns l3_protocol from ethennet packet */
static void vwd_get_l3_proto(struct sk_buff* skb, unsigned short* l3_proto)
{
	unsigned short type = 0;
	unsigned char* data_ptr;
	struct ethhdr* hdr;

	data_ptr = skb_mac_header(skb);

	hdr = (struct ethhdr *)data_ptr;

	type = htons(hdr->h_proto);
	data_ptr += ETH_HLEN;

	if( type == ETH_P_8021Q )
	{
		struct vlan_hdr *vhdr = (struct vlan_hdr *)data_ptr;
		data_ptr += VLAN_HLEN;
		type = htons(vhdr->h_vlan_encapsulated_proto);
	}
	if( type == ETH_P_PPP_SES )
	{
		struct pppoe_hdr *phdr = (struct pppoe_hdr *)data_ptr;
		if (htons(*(u16 *)(phdr+1)) == PPP_IP)
			type = ETH_P_IP;
		else if (htons(*(u16 *)(phdr+1)) == PPP_IPV6)
			type = ETH_P_IPV6;
	}

	*l3_proto = type;
}

/* This function processes all bridge packets , and send supported
	 bridge packets to DPAA for lookup and fast forwarding */
static int vwd_classify_bridge_packet( struct dpaa_vwd_priv_s *priv,struct sk_buff *skb, int *vapid)
{
	int rc = 1;
	struct vap_desc_s *vap;
	unsigned short l3_proto;
#if defined (CONFIG_VWD_MULTI_MAC)
	struct net_bridge_fdb_entry *dst = NULL;
	struct net_bridge_port *p = NULL;
	const unsigned char *dest = NULL;
	u16 vid = 0;
#endif
	spin_lock_bh(&priv->vaplock);
	vap = (struct vap_desc_s*)skb->dev->wifi_offload_dev;

	/* when a packet is received on other than wifi fastpath devices,
	 * vap can be NULL
	 */
	if (!vap)
		goto done;

	if (vap->ifindex != skb->skb_iif)
		goto done;

	*vapid = vap->vapid;
	/* packets sent to DPAA and returned from DPAA with no entry 
		 should be given to host */
	if (skb->expt_pkt == 1)
	{
		skb->expt_pkt = 0;
		goto done;
	}


	if (vwd_unsupported_eth_packet(skb))
		goto done;


#if defined (CONFIG_VWD_MULTI_MAC)
	dest = eth_hdr(skb)->h_dest;
	/* check if destination MAC matches one of the interfaces attached to the bridge */
	if((p = br_port_get_rcu(skb->dev)) != NULL)
	{
		if (br_allowed_ingress(p->br, nbp_vlan_group_rcu(p), skb, &vid)){

			dst = br_fdb_find_rcu(p->br, dest, vid);
		}
	}
	if (skb->pkt_type == PACKET_HOST || (dst && dst->is_local))
#else
		if (skb->pkt_type == PACKET_HOST)
#endif
		{
			vwd_get_l3_proto(skb, &l3_proto);
			if (l3_proto != ETH_P_IP && l3_proto != ETH_P_IPV6)
				goto done;
		}
	/*WiFi management packets received with dst address as bssid*/
		else if (!memcmp(vap->macaddr, eth_hdr(skb)->h_dest, ETH_ALEN))
		{
			goto done;
		}

	rc = 0;
done:
	spin_unlock_bh(&priv->vaplock);
	return rc;

}


static unsigned int dpaa_vwd_nf_bridge_hook_fn( void *ops, //const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int vapid = -1;

	if (!priv->fast_path_enable)
		goto done;

	if( !vwd_classify_bridge_packet(priv,skb,&vapid) )
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s: Accepted devname : %s \n", __func__,skb->dev->name);
#endif
		INCR_PER_CPU_STAT(priv->vaps[vapid].vap_stats, pkts_tx_bridge);
		skb_push(skb, ETH_HLEN);
		spin_lock_bh(&priv->txlock);
		dpaa_vwd_send_packet( priv, &priv->vaps[vapid], skb);
		spin_unlock_bh(&priv->txlock);
		return NF_STOLEN;
	}
done:
	return NF_ACCEPT;
}

/** vwd_nf_route_hook_fn
 *
 */
static unsigned int dpaa_vwd_nf_route_hook_fn( void *ops, //const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int vapid = -1;

	if (!priv->fast_path_enable)
		goto done;
	if( !vwd_classify_route_packet(priv, &skb, &vapid) )
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s: Accepted devname : %s \n", __func__,skb->dev->name);
#endif
		INCR_PER_CPU_STAT(priv->vaps[vapid].vap_stats, pkts_tx_route);
		skb_push(skb, ETH_HLEN);
		spin_lock_bh(&priv->txlock);
		dpaa_vwd_send_packet( priv, &priv->vaps[vapid], skb);
		spin_unlock_bh(&priv->txlock);
		return NF_STOLEN;
	}
done:
	return NF_ACCEPT;
}


void wifi_release_buf(struct qm_fd *fd)
{
	dma_addr_t addr;
	void *vaddr;
	struct sk_buff *skb;
	struct sk_buff **skbh;

	//get phys address and virt address
	addr = qm_fd_addr(fd);
	vaddr = phys_to_virt(addr);
	//get skb ref from buffer
	DPA_READ_SKB_PTR(skb, skbh, vaddr, -1);
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::skb:%p addr %llx\n", 
			__FUNCTION__, skb, addr);
#endif
	dev_kfree_skb(skb);
}

void disp_sglist_data(struct qm_sg_entry *sg_entry)
{
	void *vaddr;
	dma_addr_t addr;
	uint32_t len;

	while(1) {
		addr = qm_sg_addr(sg_entry);
		vaddr = ((char *)phys_to_virt(addr) + qm_sg_entry_get_offset(sg_entry));
		len = qm_sg_entry_get_len(sg_entry);
		len &= 0xffff;
		printk("sg_entry %p addr %p len %d:%d pktdata::\n", sg_entry, (void *)addr, len, sg_entry->length);
		display_buf(sg_entry, 16);
		printk("packet::\n");
		display_buf(vaddr, len);
		if(qm_sg_entry_get_final(sg_entry))
			break;
		sg_entry++;
	}
}


static inline struct sk_buff *get_skb_from_sg_list(struct qm_sg_entry *sg_entry)
{

	struct sk_buff **skbh;
	struct sk_buff *skb;
	struct sk_buff *null_skb;

	skb = NULL;
	null_skb = NULL;
	DPA_READ_SKB_PTR(skb, skbh, (uint64_t)sg_entry, -1);
	DPA_WRITE_SKB_PTR(null_skb, skbh, (uint64_t)sg_entry, -1);
	return skb;

}
static inline void release_skb_in_sglist(struct qm_sg_entry *sg_entry)
{
	struct sk_buff *skb;

	//release the skb attached to the sg list
	skb = get_skb_from_sg_list(sg_entry);
	if (skb) {
		//printk("%s::freeing skb %p\n", __FUNCTION__, skb);
		dev_kfree_skb_any(skb);
	}
}

int __hot vwd_skb_to_contig_fd(struct dpaa_vwd_priv_s *priv,
		struct sk_buff *skb, struct qm_fd *fd,
		int* offset)
{
	unsigned char *buffer_start;
	dma_addr_t addr;
	struct dpa_bp *dpa_bp = priv->txconf_bp;
	enum dma_data_direction dma_dir;
	struct sk_buff **skbh;
	//int headroom = 128;


	fd->bpid = priv->txconf_bp->bpid;
	buffer_start = skb->data - skb_headroom(skb);
	fd->offset = skb_headroom(skb);

	dma_dir = DMA_TO_DEVICE;

	//DPAWIFI_INFO("%s::headroom :%d - %d - %d \n", __FUNCTION__, priv->tx_headroom, skb_headroom(skb), skb->len);
	//DPAWIFI_INFO("%s::skb :%p - %p - %p\n", __FUNCTION__, skb, skb->data, skb->head);

	DPA_WRITE_SKB_PTR(skb, skbh, buffer_start, 0);

	*offset = skb_headroom(skb) - fd->offset;

	/* Fill in the rest of the FD fields */
	fd->format = qm_fd_contig;
	fd->length20 = skb->len;
	//fd->cmd |= FM_FD_CMD_FCO;

	/* Map the entire buffer size that may be seen by FMan, but no more */
	addr = dma_map_single(dpa_bp->dev, skbh,
			skb_tail_pointer(skb) - buffer_start, dma_dir);
	if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		DPAWIFI_ERROR("%s::DMA MAPPING ERROR :\n", __FUNCTION__);
		return -EINVAL;
	}

	qm_fd_addr_set64(fd, addr);

	return 0;

}

#ifdef DPA_SG_SUPPORT
int __hot custom_vwd_skb_to_sg_fd(struct dpaa_vwd_priv_s *priv,
		struct sk_buff *skb, struct qm_fd *fd)
{
	struct dpa_bp *dpa_bp = priv->txconf_bp;
	dma_addr_t addr;
	dma_addr_t sg_addr;
	struct sk_buff **skbh;
	int sg_len, sgt_size;
	int err;

	struct qm_sg_entry *sgt;
	void *sgt_buf;
	skb_frag_t *frag;
	int i = 0, j = 0;
	int nr_frags;
	const enum dma_data_direction dma_dir = DMA_TO_DEVICE;

	nr_frags = skb_shinfo(skb)->nr_frags;

	fd->format = qm_fd_sg;

	/* The FMan reads 256 bytes from the start of the SGT regardless of
	 * its size. In accordance, we reserve the same amount of memory as
	 * well.
	 */
	sgt_size = DPA_SGT_SIZE;

	/* Get a page frag to store the SGTable, or a full page if the errata
	 * is in place and we need to avoid crossing a 4k boundary.
	 */
#ifdef FM_ERRATUM_A050385
	if (unlikely(fm_has_errata_a050385())) {
		struct page *new_page = alloc_page(GFP_ATOMIC);

		if (unlikely(!new_page))
			return -ENOMEM;
		sgt_buf = page_address(new_page);
	}
	else
#endif
		sgt_buf = netdev_alloc_frag(priv->eth_priv->tx_headroom + sgt_size);

	if (unlikely(!sgt_buf)) {
		dev_err(dpa_bp->dev, "netdev_alloc_frag() failed\n");
		return -ENOMEM;
	}

	/* it seems that the memory allocator does not zero the allocated mem */
	memset(sgt_buf, 0, priv->eth_priv->tx_headroom + sgt_size);

	/* Assign the data from skb->data to the first SG list entry */
	sgt = (struct qm_sg_entry *)(sgt_buf + priv->eth_priv->tx_headroom);
	sg_len = skb_headlen(skb);
	qm_sg_entry_set_bpid(&sgt[0], 0xff);
	qm_sg_entry_set_offset(&sgt[0], 0);
	qm_sg_entry_set_len(&sgt[0], sg_len);
	qm_sg_entry_set_ext(&sgt[0], 0);
	if( nr_frags == 0)
		qm_sg_entry_set_final(&sgt[0], 1);
	else
		qm_sg_entry_set_final(&sgt[0], 0);

	addr = dma_map_single(dpa_bp->dev, skb->data, sg_len, dma_dir);

	if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		dev_err(dpa_bp->dev, "DMA mapping failed");
		err = -EINVAL;
		goto sg0_map_failed;
	}

	qm_sg_entry_set64(&sgt[0], addr);

	/* populate the rest of SGT entries */
	for (i = 1; i <= nr_frags; i++) {
		frag = &skb_shinfo(skb)->frags[i - 1];
		qm_sg_entry_set_bpid(&sgt[i], 0xff);
		qm_sg_entry_set_offset(&sgt[i], 0);
		qm_sg_entry_set_len(&sgt[i], frag->bv_len);
		qm_sg_entry_set_ext(&sgt[i], 0);

		if (i == nr_frags)
			qm_sg_entry_set_final(&sgt[i], 1);
		else
			qm_sg_entry_set_final(&sgt[i], 0);

		DPA_BUG_ON(!skb_frag_page(frag));
		addr = skb_frag_dma_map(dpa_bp->dev, frag, 0, frag->bv_len,
				dma_dir);
		if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
			dev_err(dpa_bp->dev, "DMA mapping failed");
			err = -EINVAL;
			goto sgt_map_failed;
		}

		/* keep the offset in the address */
		qm_sg_entry_set64(&sgt[i], addr);
	}

	fd->length20 = skb->len;
	fd->offset = priv->eth_priv->tx_headroom;

	/* DMA map the SGT page
	 *
	 * It's safe to store the skb back-pointer inside the buffer since
	 * S/G frames are non-recyclable.
	 */
	DPA_WRITE_SKB_PTR(skb, skbh, sgt_buf, 0);
	addr = dma_map_single(dpa_bp->dev, sgt_buf,
			priv->eth_priv->tx_headroom + sgt_size,
			dma_dir);

	if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		dev_err(dpa_bp->dev, "DMA mapping failed");
		err = -EINVAL;
		goto sgt_map_failed;
	}
	qm_fd_addr_set64(fd, addr);
	fd->bpid = priv->txconf_bp->bpid;
	return 0;

sgt_map_failed:
	for (j = 0; j < i; j++) {
		sg_addr = qm_sg_addr(&sgt[j]);
		dma_unmap_page(dpa_bp->dev, sg_addr,
				qm_sg_entry_get_len(&sgt[j]), dma_dir);
	}
sg0_map_failed:
	put_page(virt_to_head_page(sgt_buf));

	return err;

}
#endif

/**
 * vwd_skb_to_sg_fd
 *
 */
int __hot vwd_skb_to_sg_fd(struct dpaa_vwd_priv_s *priv,
		struct sk_buff *skb, struct qm_fd *fd)
{
	dma_addr_t addr;
	void *ptr;
	//enum dma_data_direction dma_dir;
	struct bm_buffer bmb;
	char *buffer_start;
	struct net_device **devh;
	//	int *count_ptr;
	struct vap_desc_s *vap = (struct vap_desc_s *)skb->dev->wifi_offload_dev;

	if (bman_acquire(priv->tx_bp->pool, &bmb, 1, 0) != 1) {
		DPAWIFI_ERROR("%s::dropped packet, pool empty\n", __FUNCTION__);
		if (vap) {
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_dropped);
		}
		goto err_ret;
	}

	fd->format = qm_fd_sg;
	fd->bpid = priv->tx_bp->bpid;

	fd->length20 = skb->len;
	fd->offset = VAPBUF_HEADROOM;

	buffer_start = (phys_to_virt((uint64_t)bmb.addr));
	ptr = (phys_to_virt((uint64_t)bmb.addr) + dpa_fd_offset(fd));

	DPA_WRITE_NETDEV_PTR(skb->dev, devh, buffer_start, 0);

	if (skb_is_nonlinear(skb))
	{
		if (skb_linearize(skb))
		{
			struct skb_shared_info *sh;
			sh = skb_shinfo(skb);
			printk(KERN_ERR "%s:: can't linearize, nr_frags: %d\n",__func__, sh->nr_frags);
			goto skb_failed;
		}
	}

	/* Copy the packet payload */
	skb_copy_from_linear_data(skb, ptr, skb->len);

	addr = dma_map_single(priv->tx_bp->dev, buffer_start, priv->tx_bp->size, DMA_TO_DEVICE);
	fd->addr = addr;

	return 0;

skb_failed:
	while (bman_release(priv->tx_bp->pool, &bmb, 1, 0))
		cpu_relax();

err_ret:
	return -1;
}
/* This function converts the fd from ipsec  and frag bufferpool to skb */
static struct sk_buff* sec_frag_fd_to_vwd_skb(const struct qm_dqrr_entry *dq, struct dpa_bp* dpa_bp)
{
	uint8_t *ptr, *skb_ptr;
	uint32_t len;
	struct sk_buff *skb;
	struct bm_buffer bmb;

	len = dq->fd.length20;
	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);

	skb = dev_alloc_skb(len + dq->fd.offset + 32);
	if (!skb) {
		DPAWIFI_ERROR("%s::skb alloc failed\n", __FUNCTION__);
		return NULL;
	}
	skb_reserve(skb, dq->fd.offset);
	skb_ptr = skb_put(skb, len);
	memcpy(skb_ptr, ptr, len);

	/* Release FD */
	bmb.bpid = dq->fd.bpid;
	bmb.addr = dq->fd.addr;
	while (bman_release(dpa_bp->pool, &bmb, 1, 0))
		cpu_relax();

	return skb;
}

static struct sk_buff *__hot contig_fd_to_vwd_skb(const struct dpa_priv_s *priv,
		const struct qm_fd *fd, int is_wifi_skb)
{
	struct dpa_bp *dpa_bp;
	dma_addr_t addr;
	void *vaddr;
	struct sk_buff *skb;
	struct sk_buff **skbh;
	ssize_t fd_off;

	/* In case of ethernet storing skb header in -1 offset, whereas in wifi
		 storing skbhdr in 0 offset*/
	int skb_hdr_off = is_wifi_skb ? 0 : -1;

	dpa_bp = dpa_bpid2pool(fd->bpid);
	if (!dpa_bp) {
		DPAWIFI_ERROR("%s::invalid buffer pool id %d\n", __FUNCTION__, fd->bpid);
		return NULL;
	}
	//get phys addressa and virt address
	addr = qm_fd_addr(fd);
	vaddr = phys_to_virt(addr);
	fd_off = dpa_fd_offset(fd);

	/* prefetch the first 64 bytes of the frame or the SGT start */
	dma_unmap_single(dpa_bp->dev, addr, dpa_bp->size, DMA_BIDIRECTIONAL);

	/*get skb ref from buffer*/
	DPA_READ_SKB_PTR(skb, skbh, vaddr, skb_hdr_off);

#ifdef DPA_WIFI_DEBUG
	if (fd_off > priv->rx_headroom) {
		DPAWIFI_ERROR("%s:: no headroom %d:%d\n", __FUNCTION__, (int)fd_off, priv->rx_headroom);
		//return NULL;
	}	
#endif

	if (is_wifi_skb)
	{
		/* skb->data is reset to head to update other parameters of skb like ethernet buffers */
		skb->data = skb->head;
	}
	else
	{

		/* We do not support Jumbo frames on LS1043 and thus we edit
		 * the skb truesize only when the 4k errata is not present.
		 */
#ifdef FM_ERRATUM_A050385
		if (likely(!fm_has_errata_a050385())) {
#else
		if (likely(!dpaa_errata_a010022)) {
#endif
			skb->truesize = SKB_TRUESIZE(dpa_fd_length(fd));
		}
	}
	skb->len = 0;
	skb_reset_tail_pointer(skb);
	skb_reserve(skb, fd_off);
	skb_put(skb, dpa_fd_length(fd));
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::skb:%p head %p data %p headroom %d\n", 
			__FUNCTION__, skb, skb->head, skb->data, skb_headroom(skb));
	DPAWIFI_INFO("%s::skb:len %d tail %d end %d\n", __FUNCTION__, skb->len, skb->tail, skb->end);
#endif
	return skb;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,3)
static int dpaa_vwd_send_packet(struct dpaa_vwd_priv_s *priv ,void *vap_handle, struct sk_buff *skb)
{
	struct vap_desc_s *vap_dev;
	struct qm_fd fd;
	struct dpa_bp *dpa_bp;
	int err = 0, i;
	int sg_flag  = 0;
	struct bm_buffer bmb;
	bool skb_changed, skb_need_wa;
#ifndef DPA_SG_SUPPORT
	struct sk_buff *nskb;
	int offset;
	bool nonlinear = 0;
#endif
	unsigned int total_num_tx_done;

	/* Flags to help optimize the A050385 errata restriction checks.
	 *
	 * First flag marks if the skb changed between the first A050385 check
	 * and the moment it's converted to an FD.
	 *
	 * The second flag marks if the skb needs to be realigned in order to
	 * avoid the errata.
	 *
	 * The flags should have minimal impact on platforms not impacted by
	 * the errata.
	 */
	skb_changed = false;
	skb_need_wa = false;
	vap_dev = (struct vap_desc_s *)vap_handle;

	percpu_var_sum(num_tx_done, total_num_tx_done);
	if ( (num_tx_sent - total_num_tx_done) >= (VAP_SG_BUF_COUNT >> 4))
		drain_bp_tx_done_bpool(priv->txconf_bp);

	percpu_var_sum(num_tx_done, total_num_tx_done);
	if ((num_tx_sent - total_num_tx_done) > oh_buff_limit)
	{
		INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_oh_buf_threshold_drop);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	clear_fd(&fd);

#ifdef DPA_SG_SUPPORT
	err = custom_vwd_skb_to_sg_fd(priv, skb, &fd);
	INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_sg);
#else
#ifdef FM_ERRATUM_A050385
	if (unlikely(fm_has_errata_a050385()) && a050385_check_skb(skb, priv->eth_priv))
		skb_need_wa = true;
#endif


	nonlinear = skb_is_nonlinear(skb);

	/* MAX_SKB_FRAGS is larger than our DPA_SGT_MAX_ENTRIES; make sure
	 * we don't feed FMan with more fragments than it supports.
	 * Btw, we're using the first sgt entry to store the linear part of
	 * the skb, so we're one extra frag short.
	 */
	if (nonlinear && !skb_need_wa &&
			likely(skb_shinfo(skb)->nr_frags < DPA_SGT_MAX_ENTRIES)) {
		INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_sg);
		/* Just create a S/G fd based on the skb */
		err = vwd_skb_to_sg_fd(priv, skb, &fd);
		sg_flag = 1;
	} else {
		/* Make sure we have enough headroom to accommodate private
		 * data, parse results, etc. Normally this shouldn't happen if
		 * we're here via the standard kernel stack.
		 */
		if (unlikely(skb_headroom(skb) < priv->eth_priv->tx_headroom)) {
			struct sk_buff *skb_new;

			INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_no_head);
			skb_new = skb_realloc_headroom(skb, priv->eth_priv->tx_headroom);
			if (unlikely(!skb_new)) {
				dev_kfree_skb(skb);
				return NETDEV_TX_OK;
			}
			dev_kfree_skb(skb);
			skb = skb_new;
			skb_changed = true;
		}

		/* We're going to store the skb backpointer at the beginning
		 * of the data buffer, so we need a privately owned skb
		 *
		 * Under the A050385 errata, we are going to have a privately
		 * owned skb after realigning the current one, so no point in
		 * copying it here in that case.
		 */

		/* Code borrowed from skb_unshare(). */
		if (skb_cloned(skb) && !skb_need_wa) {
			if(skb_headroom(skb) >= MAX_HEAD_ROOM_LEN) {
				nskb = skb_copy_expand(skb,priv->eth_priv->tx_headroom,skb_tailroom(skb),GFP_ATOMIC);
			}
			else {
				nskb = skb_copy(skb, GFP_ATOMIC);
			}
			kfree_skb(skb);
			skb = nskb;
			skb_changed = true;
			INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_cloned);
			/* skb_copy() has now linearized the skbuff. */
		} else if (unlikely(nonlinear) && !skb_need_wa) {
			INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_non_linear);
			/* We are here because the egress skb contains
			 * more fragments than we support. In this case,
			 * we have no choice but to linearize it ourselves.
			 */
#ifdef FM_ERRATUM_A050385
			/* No point in linearizing the skb now if we are going
			 * to realign and linearize it again further down due
			 * to the A050385 errata
			 */
			if (unlikely(fm_has_errata_a050385()))
				skb_need_wa = true;
			else
				err = __skb_linearize(skb);
#endif
		}
		if (unlikely(!skb || err < 0))
			/* Common out-of-memory error path */
			goto skb_to_fd_failed;

#ifdef FM_ERRATUM_A050385
		/* Verify the skb a second time if it has been updated since
		 * the previous check
		 */
		if (unlikely(fm_has_errata_a050385()) && skb_changed &&
				a050385_check_skb(skb, priv->eth_priv))
			skb_need_wa = true;

		if (unlikely(fm_has_errata_a050385()) && skb_need_wa) {
			INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_realign);
			nskb = a050385_realign_skb(skb, priv->eth_priv);
			if (!nskb)
				goto skb_to_fd_failed;
			dev_kfree_skb(skb);
			skb = nskb;
		}
#endif

		err = vwd_skb_to_contig_fd(priv, skb, &fd, &offset);
	}
#endif

	if (unlikely(err < 0))
	{
#ifdef DPA_SG_SUPPORT
		DPAWIFI_ERROR("%s:: custom_vwd_skb_to_sg_fd failed\n", __FUNCTION__);
#else
		DPAWIFI_ERROR("%s::vwd_skb_to_contig_fd failed\n", __FUNCTION__);
#endif
		goto skb_to_fd_failed;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::fqid %d(%x) cmd %08x, physaddr %llx\n", __FUNCTION__, 
			vap_dev->wlan_fq_to_fman->fqid,
			vap_dev->wlan_fq_to_fman->fqid, fd.cmd, (uint64_t)fd.addr);
#endif
	for (i = 0; i < 100000; i++) {
		err = qman_enqueue(&vap_dev->wlan_fq_to_fman->fq_base, &fd, 0);
		if (err != -EBUSY) {
			//DPAWIFI_ERROR("%s:%d :qman_enqueue failed\n", __FUNCTION__, __LINE__);
			break;

		}
	}


	//if (qman_enqueue(&vap_dev->wlan_fq_to_fman->fq_base, &fd, 0)) {
	if (err < 0) {
		DPAWIFI_ERROR("%s:%d :qman_enqueue failed\n", __FUNCTION__, __LINE__);
		goto qman_enq_failed;
	}
	num_tx_sent++;
	INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_transmitted);
	return 0;

qman_enq_failed:
	INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_dropped);
	if (sg_flag) {
		dpa_bp = dpa_bpid2pool(fd.bpid);

		memset(&bmb, 0, sizeof(struct bm_buffer));

		bmb.bpid = fd.bpid;
		bmb.addr = fd.addr;
		while (bman_release(dpa_bp->pool, &bmb, 1, 0))
			cpu_relax();
	}

skb_to_fd_failed:
	dev_kfree_skb(skb);

	return -1;
}
#else /*Linux 4_14 */
static int dpaa_vwd_send_packet(struct dpaa_vwd_priv_s *priv ,void *vap_handle, struct sk_buff *skb)
{
	struct vap_desc_s *vap_dev;
	struct qm_fd fd;
	struct dpa_bp *dpa_bp;
	int err = 0, i;
	int sg_flag  = 0;
#ifndef DPA_SG_SUPPORT
	int offset,  nonlinear = 0;
#endif
	struct bm_buffer bmb;
	unsigned int total_num_tx_done;

	vap_dev = (struct vap_desc_s *)vap_handle;
	//printk("<<<<<<<<<<<<\n");
	//printk("%s::pkt %p data %p\n", __FUNCTION__, skb, skb->data);
	//display_buf(skb->data, skb->len);

	percpu_var_sum(num_tx_done, total_num_tx_done);
	if ( (num_tx_sent - total_num_tx_done) >= (VAP_SG_BUF_COUNT >> 4))
		drain_bp_tx_done_bpool(priv->txconf_bp);

	percpu_var_sum(num_tx_done, total_num_tx_done);
	if ((num_tx_sent - total_num_tx_done) > oh_buff_limit)
	{
		INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_oh_buf_threshold_drop);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}


#ifndef CONFIG_PPC

	if (unlikely(dpaa_errata_a010022) && a010022_check_skb(skb, priv->eth_priv)) {
		//printk("%s:%d addr : %p len : %d\n", __func__, __LINE__, skb->head, skb->len);
		INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_realign);
		skb = a010022_realign_skb(skb, priv->eth_priv);
		if (!skb)
			goto skb_to_fd_failed;
	}
#endif

	memset(&fd, 0, sizeof(struct qm_fd));

#ifdef DPA_SG_SUPPORT
	err = custom_vwd_skb_to_sg_fd(priv, skb, &fd);
	INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_sg);
#else
	nonlinear = skb_is_nonlinear(skb);

	/* MAX_SKB_FRAGS is larger than our DPA_SGT_MAX_ENTRIES; make sure
	 * we don't feed FMan with more fragments than it supports.
	 * Btw, we're using the first sgt entry to store the linear part of
	 * the skb, so we're one extra frag short.
	 */
	if (nonlinear &&
			likely(skb_shinfo(skb)->nr_frags < DPA_SGT_MAX_ENTRIES)) {

		INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_sg);

		/* Just create a S/G fd based on the skb */
		err = vwd_skb_to_sg_fd(priv, skb, &fd);
		sg_flag = 1;
	} else {
		/* Make sure we have enough headroom to accommodate private
		 * data, parse results, etc. Normally this shouldn't happen if
		 * we're here via the standard kernel stack.
		 */
		if (unlikely(skb_headroom(skb) < priv->eth_priv->tx_headroom)) {
			struct sk_buff *skb_new;

			INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_no_head);
			skb_new = skb_realloc_headroom(skb, priv->eth_priv->tx_headroom);
			if (unlikely(!skb_new)) {
				dev_kfree_skb(skb);
				return NETDEV_TX_OK;
			}
			dev_kfree_skb(skb);
			skb = skb_new;
		}

		/* We're going to store the skb backpointer at the beginning
		 * of the data buffer, so we need a privately owned skb
		 */

		/* Code borrowed from skb_unshare(). */
		if (skb_cloned(skb)) {
			struct sk_buff *nskb = NULL;
			if(skb_headroom(skb) >= MAX_HEAD_ROOM_LEN) {
				nskb = skb_copy_expand(skb,priv->eth_priv->tx_headroom,skb_tailroom(skb),GFP_ATOMIC);
			}
			else {
				nskb = skb_copy(skb, GFP_ATOMIC);
			}
			kfree_skb(skb);
			skb = nskb;
			INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_cloned);
#ifndef CONFIG_PPC
			if (unlikely(dpaa_errata_a010022) &&
					a010022_check_skb(skb, priv->eth_priv)) {
				skb = a010022_realign_skb(skb, priv->eth_priv);
				if (!skb)
					goto skb_to_fd_failed;
			}
#endif
			/* skb_copy() has now linearized the skbuff. */
		} else if (unlikely(nonlinear)) {
			INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_non_linear);
			/* We are here because the egress skb contains
			 * more fragments than we support. In this case,
			 * we have no choice but to linearize it ourselves.
			 */
			err = __skb_linearize(skb);
		}
		if (unlikely(!skb || err < 0))
			/* Common out-of-memory error path */
			goto qman_enq_failed;

		err = vwd_skb_to_contig_fd(priv, skb, &fd, &offset);
	}
#endif

	if (unlikely(err < 0))
	{
#ifdef DPA_SG_SUPPORT
		DPAWIFI_ERROR("%s:: custom_vwd_skb_to_sg_fd failed\n", __FUNCTION__);
#else
		DPAWIFI_ERROR("%s::vwd_skb_to_contig_fd failed\n", __FUNCTION__);
#endif
		goto skb_to_fd_failed;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::fqid %d(%x) cmd %08x, physaddr %llx\n", __FUNCTION__, 
			vap_dev->wlan_fq_to_fman->fqid,
			vap_dev->wlan_fq_to_fman->fqid, fd.cmd, (uint64_t)fd.addr);
#endif
	for (i = 0; i < 100000; i++) {
		err = qman_enqueue(&vap_dev->wlan_fq_to_fman->fq_base, &fd, 0);
		if (err != -EBUSY) {
			//DPAWIFI_ERROR("%s:%d :qman_enqueue failed\n", __FUNCTION__, __LINE__);
			break;

		}
	}


	//if (qman_enqueue(&vap_dev->wlan_fq_to_fman->fq_base, &fd, 0)) {
	if (err < 0) {
		DPAWIFI_ERROR("%s:%d :qman_enqueue failed\n", __FUNCTION__, __LINE__);
		goto qman_enq_failed;
	}
	num_tx_sent++;
	INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_transmitted);
	return 0;

qman_enq_failed:
	INCR_PER_CPU_STAT(vap_dev->vap_stats, pkts_tx_dropped);
	if (sg_flag) {
		dpa_bp = dpa_bpid2pool(fd.bpid);

		memset(&bmb, 0, sizeof(struct bm_buffer));

		bmb.bpid = fd.bpid;
		bmb.addr = fd.addr;
		while (bman_release(dpa_bp->pool, &bmb, 1, 0))
			cpu_relax();
	}

skb_to_fd_failed:
	dev_kfree_skb(skb);

	return -1;
}
#endif

static int process_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct sk_buff *skb;
	struct dpa_bp *dpa_bp = dpa_bpid2pool(dq->fd.bpid);
	int len, sg_flag = 0;
	char *buffer_start, *ptr;
	struct net_device *dev;
	struct vap_desc_s *vap;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::exception packet\n", __FUNCTION__);
	DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d addr %llx status %08x\n", __FUNCTION__,
			dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
			dq->fd.offset,  (uint64_t)dq->fd.addr, dq->fd.status);
#endif

	len = dq->fd.length20;
	buffer_start = (phys_to_virt((uint64_t)dq->fd.addr));
	ptr = (phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);

	get_cpu_var(num_tx_done)++;
	put_cpu_var(num_tx_done);
#ifndef DPA_SG_SUPPORT
	if (dq->fd.format == qm_fd_sg) {
		struct net_device **devh;
		char *skb_ptr;

		DPA_READ_NETDEV_PTR(dev, devh, buffer_start, 0);

		skb = dev_alloc_skb(len + 2 + priv->eth_priv->tx_headroom);
		if (!skb) {
			DPAWIFI_ERROR("%s::skb alloc failed\n", __FUNCTION__);
			goto rel_fd;
		}

		/* IP ALIGNMENT */
		skb_reserve(skb, 2 + priv->eth_priv->tx_headroom);

		skb_ptr = skb_put(skb, len);
		memcpy(skb_ptr, ptr, len);
		skb->dev = dev;
		sg_flag = 1;
	} else
#endif
	{
		struct sk_buff **skbh;
#ifdef DPA_SG_SUPPORT
		struct qm_sg_entry *sgt;
		int j, nr_frags;
		dma_addr_t sg_addr;
		dma_unmap_single(dpa_bp->dev, dq->fd.addr, priv->eth_priv->tx_headroom + DPA_SGT_SIZE,
				DMA_TO_DEVICE);
#endif
		DPA_READ_SKB_PTR(skb, skbh, buffer_start, 0);
#ifdef DPA_SG_SUPPORT
		sgt = (struct qm_sg_entry *)(buffer_start + priv->eth_priv->tx_headroom);
		nr_frags = skb_shinfo(skb)->nr_frags;
		for (j = 0; j <= nr_frags; j++) {
			sg_addr = qm_sg_addr(&sgt[j]);
			dma_unmap_page(dpa_bp->dev, sg_addr,
					qm_sg_entry_get_len(&sgt[j]), DMA_TO_DEVICE);
		}

		put_page(virt_to_head_page(buffer_start));
#endif
	}

	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		DPAWIFI_ERROR("%s::unable to get skb pointer for fd\n", __FUNCTION__);
		goto rel_fd;
	}

	dev = skb->dev;
	vap = (struct vap_desc_s *)skb->dev->wifi_offload_dev;
	if (!vap)
	{
		DPAWIFI_ERROR("%s(%d) vap entry is NULL\n",__FUNCTION__,__LINE__);
		dev_kfree_skb(skb);
		goto rel_fd;
	}
	if (!vap->no_l2_itf)
	{
		skb->protocol = eth_type_trans(skb, dev);
		skb->expt_pkt = 1;
		if (netif_receive_skb(skb) == NET_RX_DROP) {
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_ERROR("%s::netif_receive_skb:NET_RX_DROP\n", __FUNCTION__);
#endif
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_path_drop);
		}
	}
	else
	{
#ifndef UNIT_TEST
		skb_pull(skb, ETH_HLEN);
		skb_reset_network_header(skb);
		skb->mac_len = 0;
		skb->expt_pkt = 1;
		if (netif_rx(skb) == NET_RX_DROP) {
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_ERROR("%s::netif_receive_skb:NET_RX_DROP\n", __FUNCTION__);
#endif
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_path_drop);
		}
#else
		skb->protocol = eth_type_trans(skb, dev);
		skb->expt_pkt = 1;
		if (netif_receive_skb(skb) == NET_RX_DROP) {
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_ERROR("%s::netif_receive_skb:NET_RX_DROP\n", __FUNCTION__);
#endif
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_path_drop);
		}
#endif /* UNIT_TEST */		
	}
	INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_forwarded);
rel_fd:
	if (sg_flag){
		struct bm_buffer bmb;

		memset(&bmb, 0, sizeof(struct bm_buffer));

		bmb.bpid = dq->fd.bpid;
		bmb.addr = dq->fd.addr;
		while (bman_release(dpa_bp->pool, &bmb, 1, 0))
			cpu_relax();
	}
	return 0;
}

static int add_device_tx_bpool(struct dpaa_vwd_priv_s  *vwd)
{

	struct dpa_bp *bp, *bp_parent;
	int buffer_count = 0, ret = 0, refill_cnt ;


	bp = kzalloc(sizeof(struct dpa_bp), 0);
	if (unlikely(bp == NULL)) {
		DPAWIFI_ERROR("%s::failed to allocate mem for bman pool for dev %s\n",
				__FUNCTION__,vwd->name);
		return -1;
	}
	bp->size = VAPDEV_BUFSIZE;
	bp->config_count = VAPDEV_BUFCOUNT;
	if (get_phys_port_poolinfo_bysize(VAPDEV_BUFSIZE, &vwd->parent_pool_info)) {
		DPAWIFI_ERROR("%s::failed to locate eth bman pool for dev %s\n", __FUNCTION__, vwd->name);
		bman_free_pool(bp->pool);
		kfree(bp);
		return -1;
	}

	vwd->tx_bp = bp;

	bp_parent = dpa_bpid2pool(vwd->parent_pool_info.pool_id);
	bp->dev = bp_parent->dev;

	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAWIFI_ERROR("%s::dpa_bp_alloc failed for dev %s\n", __FUNCTION__,vwd->name);
		kfree(bp);
		return -1;
	}

	while (buffer_count < VAPDEV_BUFCOUNT)
	{
		refill_cnt = 0;
		ret = dpaa_eth_refill_bpools(bp, &refill_cnt,
			CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD);
		if (ret < 0)
		{
			DPAWIFI_ERROR("%s:: Error returned for dpaa_eth_refill_bpools %d\n", __FUNCTION__,ret);
			break;
		}

		buffer_count += refill_cnt;
	}
	bp->config_count = buffer_count;

	DPAWIFI_INFO("%s::TX buffers_allocated %d - %d\n", __FUNCTION__,bp->config_count, bp->bpid);
	return 0;

}

void drain_tx_bp_pool(struct dpa_bp *bp)
{
	int ret, num = 8;

	do {
		struct bm_buffer bmb[8];
		int i;

		ret = bman_acquire(bp->pool, bmb, num, 0);
		if (ret < 0) {
			if (num == 8) {
				/* we have less than 8 buffers left;
				 * drain them one by one
				 */
				num = 1;
				ret = 1;
				continue;
			} else {
				/* Pool is fully drained */
				break;
			}
		}

		for (i = 0; i < num; i++) {
			dma_addr_t addr = bm_buf_addr(&bmb[i]);

			dma_unmap_single(bp->dev, addr, bp->size,
					DMA_BIDIRECTIONAL);

			_dpa_bp_free_pf(phys_to_virt(addr));
		}
	} while (ret > 0);
}


enum qman_cb_dqrr_result vwd_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{

	struct dpa_priv_s               *priv = vwd.eth_priv;
	struct dpa_percpu_priv_s        *percpu_priv;

	DPA_BUG_ON(priv);
	/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);

#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
		return qman_cb_dqrr_stop;
#endif

	process_rx_exception_pkt(portal, fq, dq);	
	return qman_cb_dqrr_consume;
}


void vwd_send_to_vap(struct sk_buff* skb)
{
	struct ethhdr *hdr;

	hdr = (struct ethhdr *)skb->data;
	skb->protocol = hdr->h_proto;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
	skb->mac.raw = skb->data;
	skb->nh.raw = skb->data + sizeof(struct ethhdr);
#else
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, sizeof(struct ethhdr));
#endif
	skb->priority = 0;
	original_dev_queue_xmit(skb);
	return;
}

static enum qman_cb_dqrr_result vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{

#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	struct dpa_priv_s               *priv = vwd.eth_priv;
	struct dpa_percpu_priv_s        *percpu_priv;
	struct dpa_bp	*dpa_bp = priv->dpa_bp;

	DPA_BUG_ON(priv);
	/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);

	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
		return qman_cb_dqrr_stop;
#endif
	process_vap_rx_fwd_pkt(portal, fq, dq);
	return qman_cb_dqrr_consume;
}

static int process_vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq, const struct qm_dqrr_entry *dq )
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct sk_buff *skb;
	struct net_device *net_dev;
	struct dpa_bp *dpa_bp, *ipsec_bp, *frag_bp;
	struct vap_desc_s *vap; 
	int *count_ptr, wifi_skb = 1;

	dpa_bp = dpa_bpid2pool(dq->fd.bpid);
	net_dev = ((struct dpa_fq *)fq)->net_dev;
	if (dpa_bp == priv->txconf_bp)
	{
		get_cpu_var(num_tx_done)++;
		put_cpu_var(num_tx_done);
	}
	/*If vap interface is down then fq net_dev is NULL, in this case release the fd.*/
	if (!net_dev)
	{
		if (printk_ratelimit())
			DPAWIFI_ERROR("%s::vap interface is down, releasing the frame from fq %u.\n ", 
							__FUNCTION__, fq->fqid);
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_dev_down_drop);
		goto rel_fd;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::forwarding packet\n", __FUNCTION__);
	DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d netdev %p dev %s addr %llx\n", __FUNCTION__,
			dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
			dq->fd.offset, net_dev, net_dev->name, (uint64_t)dq->fd.addr);
#endif
	/* The only FD types that we may receive are contig and S/G */
	if (dq->fd.format != qm_fd_contig) {
		DPAWIFI_ERROR("%s::TBD discarding SG frame :%d\n ", __FUNCTION__,dq->fd.format);
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		goto rel_fd;
	}

	/* If the packet is recieved from ipsec, then the buffer used is not
	   from ethernet buffer pool or from kernel, so this buffer has to be
	   copied to skb and to be sent to wifi driver, and the buffer from ipsec bufferpool 
	   is released */ 
	ipsec_bp = get_ipsec_bp();
	/* If the packet is fragmented in fast path, then one of the packet will be received
	   from fragment buffer pool */
	frag_bp  = get_frag_bp();
	if ( (dpa_bp == ipsec_bp) || (dpa_bp == frag_bp) )
	{
		/* Process secure packet transmitted to wifi */
		skb = sec_frag_fd_to_vwd_skb(dq, dpa_bp);
		goto process_skb;
	}
	/* Check if buffer is from ethernet pool to refill buffer pool 
	   for wifi packets, buffers are skb buffers and they will get freed to kernel */
	if ( (dpa_bp != priv->txconf_bp) && (dpa_bp != priv->tx_bp))
	{
		wifi_skb = 0;
		count_ptr = raw_cpu_ptr(dpa_bp->percpu_count);
		if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
				CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD))) {
			//if we cant refill give this up
			goto rel_fd;
		}
		*count_ptr -= 1;
	}

	skb = contig_fd_to_vwd_skb(priv->eth_priv, &dq->fd, wifi_skb);

	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		DPAWIFI_ERROR("%s::contig_fd_to_vwd_skb failed\n", __FUNCTION__);
		goto rel_fd;
	}

process_skb:
	skb->dev = net_dev;
	vap = (struct vap_desc_s *)net_dev->wifi_offload_dev;

	/* vap must not be NULL */
	if (!vap)
	{
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		DPAWIFI_ERROR("%s(%d) vap entry is NULL\n",__FUNCTION__,__LINE__);
		dev_kfree_skb(skb);
		return 0;
	}

	INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_fast_forwarded);
	if (dpa_bp == ipsec_bp) {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_ipsec);
	}

	/* check if vap is corresponding to no l2 hdr */
	if (!vap->no_l2_itf)
		vwd_send_to_vap(skb);
	else
	{
#ifndef UNIT_TEST
		/* Set the protocol before giving it to stack */
		/* skip the ethernet header in skb, then transmit */
		struct ethhdr *hdr;

		hdr = (struct ethhdr *)skb->data;
		skb->protocol = hdr->h_proto;

		skb_pull(skb, ETH_HLEN);
		skb_reset_network_header(skb);
		skb->mac_len = 0;
#else
		{
			struct ethhdr *hdr;

			hdr = (struct ethhdr *)skb->data;
			skb->protocol = hdr->h_proto;
			skb_reset_mac_header(skb);
			skb_set_network_header(skb, sizeof(struct ethhdr));
		}
#endif /* UNIT_TEST */
		skb->priority = 0;
		original_dev_queue_xmit(skb);
	}
	return 0;

rel_fd: 
	{
		struct bm_buffer bmb;

		memset(&bmb, 0, sizeof(struct bm_buffer));
		bmb.bpid = dq->fd.bpid;
		bmb.addr = dq->fd.addr;
		while (bman_release(dpa_bp->pool, &bmb, 1, 0))
			cpu_relax();	
	}
	return 0;
}


static int vwd_init_pcd_fqs(struct dpaa_vwd_priv_s *priv)
{
	uint32_t fqbase;
	uint32_t fqcount;
	uint32_t portid;
	uint32_t ii,jj;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals, max_dist;
	uint32_t next_portal_ch_idx;
	const cpumask_t *affine_cpus;
	struct dpa_fq *dpa_fq;
	struct dpa_iface_info *oh_iface_info;
	struct qman_fq *fq;

	/*get cpu portal channel info */
	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}
	if (!num_portals) {
		DPAWIFI_ERROR("%s::unable to get affined portal info\n", __FUNCTION__);
		return -1;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::num_portals %d ::", __FUNCTION__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPAWIFI_INFO("%d ", portal_channel[ii]);
	DPAWIFI_INFO("\n");
#endif

	if (get_ofport_max_dist(FMAN_IDX, priv->oh_port_handle, &max_dist) < 0)
	{
		DPAWIFI_ERROR("%s::unable to get distributions for oh port\n", __FUNCTION__);
		return -1;
	}

	for(jj = 0;jj < max_dist; jj++)
	{

		if (get_oh_port_pcd_fqinfo(FMAN_IDX, priv->oh_port_handle, 
					jj, &fqbase, &fqcount)) {
			DPAWIFI_ERROR("%s::err getting pcd fq\n", __FUNCTION__) ;
			return -1;
		}
		/*get port id required for FQ creation*/
		if (get_ofport_portid(FMAN_IDX, priv->oh_port_handle, &portid)) {
			DPAWIFI_ERROR("%s::err getting of port id\n", __FUNCTION__) ;
			return -1;
		}
		DPAWIFI_INFO("%s::pcd FQ base for portid %d  dist %x(%d), count %d\n",
				__FUNCTION__, portid, fqbase, fqbase, fqcount);

		if ((oh_iface_info = dpa_get_ohifinfo_by_portid(portid)) == NULL) {
			DPAWIFI_ERROR("%s::err getting oh iface info of port id %u\n", __FUNCTION__, portid) ;
			return -1;
		}
		if (oh_iface_info->pcd_proc_entry == NULL)
		{
			DPAWIFI_ERROR("%s()::%d OH iface pcd proc entry is invalid:\n", __func__, __LINE__);
			return -1;
		}

		/*alloc for as many fqs as required */
		priv->wlan_exception_fq = kzalloc((sizeof(struct dpa_fq) * fqcount), 1);
		if (!priv->wlan_exception_fq) {
			DPAWIFI_ERROR("%s::err allocating fq mem\n", __FUNCTION__) ;
			return -1;
		}
		/*save dpa_fq base info */
		dpa_fq = priv->wlan_exception_fq;
		/*add port id into FQID */
		fqbase |= (portid << PORTID_SHIFT_VAL);
		/*create all FQs */
		priv->expt_fq_count = 0;
		for (ii = 0; ii < fqcount; ii++) {
			struct qm_mcc_initfq opts;

			memset(dpa_fq, 0, sizeof(struct dpa_fq));
			/*set FQ parameters 
			  dpa_fq->net_dev = vap->wifi_dev; */
			dpa_fq->fq_type = FQ_TYPE_RX_PCD;
			dpa_fq->fqid = fqbase;
			/*set call back function pointer*/
			fq = &dpa_fq->fq_base;
			fq->cb.dqrr = vwd_rx_exception_pkt;
			/*round robin channel like ethernet driver does */
			dpa_fq->channel = portal_channel[next_portal_ch_idx];
			if (next_portal_ch_idx == (num_portals - 1))
				next_portal_ch_idx = 0;
			else
				next_portal_ch_idx++;
			dpa_fq->wq = DEFA_WQ_ID;
			/*set options similar to ethernet driver */
			memset(&opts, 0, sizeof(struct qm_mcc_initfq));
			opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
			opts.fqd.context_a.stashing.exclusive =
				(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
			opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
			opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
			/*create FQ */
			if (qman_create_fq(dpa_fq->fqid, 0, fq)) {
				DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
						__FUNCTION__, dpa_fq->fqid);
				goto err_ret;
			}
			opts.fqid = dpa_fq->fqid;
			opts.count = 1;
			opts.fqd.dest.channel = dpa_fq->channel;
			opts.fqd.dest.wq = dpa_fq->wq;
			opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
					QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);

			/*init FQ */
			if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
				DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
						__FUNCTION__, dpa_fq->fqid);
				qman_destroy_fq(fq, 0);
				goto err_ret;
			}

			cdx_create_type_fqid_info_in_procfs(fq, PCD_DIR, oh_iface_info->pcd_proc_entry, NULL);
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_INFO("%s::created pcd fq %x(%d) for wlan packets "
					"channel 0x%x\n", __FUNCTION__,
					dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
			/*next FQ */
			dpa_fq++;
			fqbase++;
			priv->expt_fq_count++;
		}
	}
	return 0;
err_ret:
	/* FIXME: jj index loop is missing. In present case it is single loop, so no issue.*/
	/* release FQs allocated so far and mem */
	/* Present ii index fq already destroyed before goto, 
		so here it is checking ii > 0 instead of ii >=0 */
	for (; ii>0 ; ii--)
	{
		dpa_fq--;
		fq = &dpa_fq->fq_base;
		if (qman_retire_fq(fq, NULL)) {
			DPAWIFI_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			continue;
		}
		if (qman_oos_fq(fq)) {
			DPAWIFI_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
			continue;
		}
		cdx_remove_fqid_info_in_procfs(fq->fqid);
		qman_destroy_fq(fq, 0);
		priv->expt_fq_count--;
	}
	kfree(priv->wlan_exception_fq);
	return -1;
}

static int create_vap_fwd_from_fman_fqs(struct vap_desc_s *vap, void *proc_entry)
{
	uint32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals;
	const cpumask_t *affine_cpus;

	/* get cpu portal channel info */
	num_portals = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}

	if (!num_portals) {
		DPAWIFI_ERROR("%s::unable to get affined portal info\n",
				__FUNCTION__);
		return -1;
	}

	for (ii = 0; ii < CDX_VWD_FWD_FQ_MAX; ii++) {
		uint32_t flags;

		/* create FQ for forward from DPAA to wireless interface */
		dpa_fq = kzalloc(sizeof(struct dpa_fq), 0);

		if (!dpa_fq) {
			DPAWIFI_ERROR("%s::unable to alloc mem for dpa_fq\n", __FUNCTION__) ;
			return -1;
		}
		memset(dpa_fq, 0, sizeof(struct dpa_fq));
		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		fq = &dpa_fq->fq_base;
		flags = 0;

		/* fwd fq */
		fq->cb.dqrr = vap_rx_fwd_pkt;
		if (cdx_copy_eth_rx_channel_info(FMAN_IDX, dpa_fq)) {
			DPAWIFI_ERROR("%s::unable to get cpu channel info\n", __FUNCTION__) ;
			kfree(dpa_fq);
			return -1;
		}

		/* opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE); */
		opts.fqd.context_a.stashing.exclusive =
			(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
		opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
		opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
		dpa_fq->fq_type = FQ_TYPE_RX_PCD;
		dpa_fq->wq = DEFA_VWD_WQ_ID;
		dpa_fq->net_dev = vap->wifi_dev;

		if (!dpa_fq->fqid)
			flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;

		if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
			DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
					__FUNCTION__, dpa_fq->fqid);
			kfree(dpa_fq);
			return -1;
		}

		dpa_fq->channel = portal_channel[ii % num_portals];

		dpa_fq->fqid = fq->fqid;
		opts.fqid = dpa_fq->fqid;
		opts.count = 1;
		opts.fqd.dest.channel = dpa_fq->channel;
		opts.fqd.dest.wq = dpa_fq->wq;
		opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
		if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
			DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
					__FUNCTION__, dpa_fq->fqid);
			qman_destroy_fq(fq, 0);
			kfree(dpa_fq);
			return -1;
		}	

		/* TX OH2 */
		cdx_create_type_fqid_info_in_procfs(fq, TX_DIR, proc_entry, NULL);
		vap->wlan_fq_from_fman[ii] = dpa_fq;

#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s::created fq %x(%d) for wlan packets "
				"channel 0x%x\n", __FUNCTION__,
				dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
	}

	return 0;
}

static int create_vap_fqs(struct vap_desc_s *vap)
{
	//uint32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	struct dpa_fq **dpa_fq_ptr;
	struct dpa_iface_info *oh_iface_info;
	uint32_t flags;
	uint32_t portid;


	/*get port id required for FQ creation*/
	if (get_ofport_portid(FMAN_IDX, vap->vwd->oh_port_handle, &portid)) {
		DPAWIFI_ERROR("%s::err getting of port id\n", __FUNCTION__) ;
		return -1;
	}
	DPAWIFI_INFO("%s:portid %d \n", __FUNCTION__, portid);

	if ((oh_iface_info = dpa_get_ohifinfo_by_portid(portid)) == NULL) {
		DPAWIFI_ERROR("%s::err getting oh iface info of port id %u\n", __FUNCTION__, portid) ;
		return -1;
	}
	if (oh_iface_info->tx_proc_entry == NULL)
	{
		DPAWIFI_ERROR("%s()::%d OH iface tx proc entry is invalid:\n", __func__, __LINE__);
		return -1;
	}

	if (create_vap_fwd_from_fman_fqs(vap, oh_iface_info->tx_proc_entry)) {
		DPAWIFI_ERROR("%s::unable to create fwd fqs\n", __FUNCTION__) ;
		return -1;
	}

	if (oh_iface_info->rx_proc_entry == NULL)
	{
		DPAWIFI_ERROR("%s()::%d OH iface rx proc entry is invalid:\n", __func__, __LINE__);
		return -1;
	}


	/* create FQ for exception packets from wireless interface */
	dpa_fq = kzalloc(sizeof(struct dpa_fq), 0);
	if (!dpa_fq) {
		DPAWIFI_ERROR("%s::unable to alloc mem for dpa_fq\n", __FUNCTION__) ;
		return -1;
	}
	memset(dpa_fq, 0, sizeof(struct dpa_fq));
	memset(&opts, 0, sizeof(struct qm_mcc_initfq));
	fq = &dpa_fq->fq_base;
	dpa_fq_ptr = NULL;
	flags = 0;
	/* offline port fq */
	flags |= QMAN_FQ_FLAG_TO_DCPORTAL;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	dpa_fq->channel = vap->channel;
	/* contexta, b  */
	opts.fqd.context_a.hi = 0; //0x12000000; //OVFQ, A2V, OVOM
	opts.fqd.context_a.lo = 0x00000000; //0;
	dpa_fq->fq_type = FQ_TYPE_RX_PCD;
	dpa_fq->wq = DEFA_VWD_WQ_ID;
	dpa_fq->net_dev = vap->wifi_dev;
	if (!dpa_fq->fqid)
		flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;
	if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
		DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
				__FUNCTION__, dpa_fq->fqid);
		kfree(dpa_fq);
		return -1;
	}

	dpa_fq->fqid = fq->fqid;
	opts.fqid = dpa_fq->fqid;
	opts.count = 1;
	opts.fqd.dest.channel = dpa_fq->channel;
	opts.fqd.dest.wq = dpa_fq->wq;
	opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
	if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
		DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
				__FUNCTION__, dpa_fq->fqid);
		qman_destroy_fq(fq, 0);
		kfree(dpa_fq);
		return -1;
	}	

	/* RX OH2 */
	cdx_create_type_fqid_info_in_procfs(fq, RX_DIR, 
				oh_iface_info->rx_proc_entry, NULL);
	vap->wlan_fq_to_fman = dpa_fq;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::created fq %x(%d) for wlan packets "
			"channel 0x%x\n", __FUNCTION__,
			dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
	return 0;
}

/* Destroys Frame Queues */
static void vwd_fq_destroy(struct qman_fq *fq)
{
	int _errno = 0;

	_errno = qman_retire_fq(fq, NULL);
	if (unlikely(_errno < 0)){
		DPAWIFI_ERROR("%s: Error in retire_fq: %u with error:%d\n", __FUNCTION__, qman_fq_fqid(fq), _errno);
	}

	_errno = qman_oos_fq(fq);
	if (unlikely(_errno < 0)) {
		DPAWIFI_ERROR("%s: Error in retire_fq: %u with error:%d\n", __FUNCTION__, qman_fq_fqid(fq), _errno);
	}

	cdx_remove_fqid_info_in_procfs(fq->fqid);

	qman_destroy_fq(fq, 0);
}


static int release_vap_fqs(struct vap_desc_s *vap)
{
	int i;
	/* This WLAN exception FQ is used for all vwd interfaces */
	/* TODO - Need to modify to delete only for last interface, and add 
	   for 1st interface */	
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: vwd count :%d\n", __func__, vap->vwd->expt_fq_count);
#endif

	for (i = 0; i < CDX_VWD_FWD_FQ_MAX; i++) {
		if (vap->wlan_fq_from_fman[i])
		{
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_INFO("%s:: releasing fq from fman :%d\n", __func__, vap->wlan_fq_from_fman[i]->fqid);
#endif
			vwd_fq_destroy(&vap->wlan_fq_from_fman[i]->fq_base);
			kfree(vap->wlan_fq_from_fman[i]);
			vap->wlan_fq_from_fman[i] = NULL;
		}
	}

	if (vap->wlan_fq_to_fman)
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:: releasing fq to fman :%d\n", __func__, vap->wlan_fq_to_fman->fqid);
#endif
		vwd_fq_destroy(&vap->wlan_fq_to_fman->fq_base);
		kfree(vap->wlan_fq_to_fman);
		vap->wlan_fq_to_fman = NULL;
	}
	return 0;
}

int dpaa_get_vap_fwd_fq(uint16_t vap_id, uint32_t* fqid, uint32_t hash)
{
	*fqid = vwd.vaps[vap_id].wlan_fq_from_fman[hash & (CDX_VWD_FWD_FQ_MAX - 1)]->fqid;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: fwd_fq :%x\n",__func__, *fqid);
#endif
	return 0;
}

/* This function returns net dev with VAP id */
int dpaa_get_wifi_dev(uint16_t vap_id, void** netdev)
{
	*netdev = (void*)vwd.vaps[vap_id].wifi_dev;
	return 0;
}

/* This function returns  WIFI related OH port handle */
int dpaa_get_wifi_ohport_handle( uint32_t* oh_handle)
{
	*oh_handle = vwd.oh_port_handle;
	return 0;
}
#if 0
//call under vaplock, retuenrs true if device is found
static int find_vapdev_by_name(char *devname, struct vap_desc_s **freedev)
{
	int retval;
	uint16_t ii;
	struct vap_desc_s *vapdev;
	struct vap_desc_s *freevapdev;

	vapdev = &vwd.vaps[0];
	freevapdev = NULL;
	retval = 0;
	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		if (vapdev->state == VAP_ST_CLOSE) {
			if (!freevapdev) {
				freevapdev = vapdev;
				vapdev->vapid = ii;
				vapdev->vwd = &vwd;
			}
		} else {
			if (!strcmp(devname, vapdev->ifname)) {
				DPAWIFI_ERROR("%s::device %s already associated\n", 
						__FUNCTION__, devname);
				retval = 1;
				break;
			}
		}
		vapdev++;
	}
	if (freedev)
		*freedev = freevapdev;
	return retval;
}

static int fill_sg_pool(struct dpa_bp *bp)
{
	void *new_buf;
	dma_addr_t addr;
	struct page *new_page;
	struct bm_buffer bmb[8];
	uint32_t count;
	uint32_t fill_count;
	uint32_t ii;
	int err;
	struct device *dev;

	dev = bp->dev;
	count = 0;
	err = 0;
	while(1) {
		fill_count = (bp->config_count - count);
		if (!fill_count)
			break;
		if (fill_count > 8)
			fill_count = 8;
		for (ii = 0; ii < fill_count; ii++) {
			new_page = alloc_page(GFP_ATOMIC);
			if (unlikely(!new_page)) {
				err = -1;
				break;
			}
			new_buf = page_address(new_page);
			get_skb_from_sg_list(new_buf + VAP_SG_BUF_HEAD_ROOM);
			addr = dma_map_single(dev, new_buf,
					bp->size, DMA_BIDIRECTIONAL);
			if (unlikely(dma_mapping_error(dev, addr))) {
				err = -1;
				kfree(new_buf);
				break;
			}
			bm_buffer_set64(&bmb[ii], addr);
			bmb[ii].bpid = bp->bpid;
		}
		count += ii;
		if (ii) {
			while (unlikely(bman_release(bp->pool, bmb, ii, 0)))
				cpu_relax();
		}
		if (err)
			break;
	}
	printk("%s::filled %d buffers into pool %d\n", __FUNCTION__,
			count, bp->bpid);
	return 0;
}

#endif

static int add_device_tx_done_bpool(struct dpaa_vwd_priv_s  *vwd)
{
	struct dpa_bp *bp;
	struct dpa_bp *bp_parent;

	if (get_phys_port_poolinfo_bysize(VAPDEV_BUFSIZE, &vwd->parent_pool_info)) {
		DPAWIFI_ERROR("%s::failed to locate eth bman pool for dev %s\n", __FUNCTION__, vwd->name);
		return -1;
	}
	bp_parent = dpa_bpid2pool(vwd->parent_pool_info.pool_id);

	bp = kzalloc(sizeof(struct dpa_bp), 0);

	if (unlikely(bp == NULL)) {
		DPAWIFI_ERROR("%s::failed to allocate mem for bman pool for dev %s\n",
				__FUNCTION__,vwd->name);
		return -1;
	}
	bp->size = VAPDEV_BUFSIZE;
	bp->config_count = VAP_SG_BUF_COUNT;
	vwd->txconf_bp = bp;
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAWIFI_ERROR("%s::dpa_bp_alloc failed for dev %s\n", __FUNCTION__, vwd->name);
		kfree(bp);
		return -1;
	}
	printk("%s::txconf bpid %d, for dev %s\n", __FUNCTION__, bp->bpid, vwd->name);

	return 0;
}

void drain_bp_tx_done_bpool(struct dpa_bp *bp)
{
	int ret, num = 8;
#ifdef DPA_SG_SUPPORT
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct qm_sg_entry *sgt;
	dma_addr_t sg_addr;
	int j=0,nr_frags;
#endif

	//printk("%s:%d sent:done %d:%d\n", __func__, __LINE__, num_tx_sent, num_tx_done);

	do {
		struct bm_buffer bmb[8];
		int i;

		ret = bman_acquire(bp->pool, bmb, num, 0);
		if (ret < 0) {
			if (num == 8) {
				/* we have less than 8 buffers left;
				 * drain them one by one
				 */
				num = 1;
				ret = 1;
				continue;
			} else {
				/* Pool is fully drained */
				break;
			}
		}

		for (i = 0; i < num; i++) {
			struct sk_buff *skb, **skbh;
			void *vaddr;

			dma_addr_t addr = bm_buf_addr(&bmb[i]);

			dma_unmap_single(bp->dev, addr, bp->size,
					DMA_BIDIRECTIONAL);

			//release the skb attached to the sg list
			addr = bm_buf_addr(&bmb[i]);
			vaddr = phys_to_virt((uint64_t)addr);

			DPA_READ_SKB_PTR(skb, skbh, vaddr, 0);

#ifdef DPA_WIFI_DEBUG
			DPAWIFI_INFO("%s::buff from txconf pool %d addr %p\n",
					__FUNCTION__, bp->bpid, (void *)(uint64_t)bmb[i].addr);
#endif
			if (skb) {
				//      printk("%s::freeing skb %p\n", __FUNCTION__, tmp_skb);
				//Unmap packet data
#ifdef DPA_SG_SUPPORT
				sgt = (struct qm_sg_entry *)(vaddr + priv->eth_priv->tx_headroom);
				nr_frags = skb_shinfo(skb)->nr_frags;
				for (j = 0; j <= nr_frags; j++) {
					sg_addr = qm_sg_addr(&sgt[j]);
					dma_unmap_page(bp->dev, sg_addr,
							qm_sg_entry_get_len(&sgt[j]), DMA_TO_DEVICE);
				}
#endif
				dev_kfree_skb_any(skb);
			}
#ifdef DPA_SG_SUPPORT
			put_page(virt_to_head_page(vaddr));
#endif
			get_cpu_var(num_tx_done)++;
			put_cpu_var(num_tx_done);


		}
	} while (ret > 0);

	//    printk("%s:%d sent:done %d:%d\n", __func__, __LINE__, num_tx_sent, num_tx_done);
}

static int release_device_tx_done_bpool(struct dpaa_vwd_priv_s  *vwd)
{
	if (!vwd->txconf_bp)
		return 0;
	drain_bp_tx_done_bpool(vwd->txconf_bp);
	vwd->txconf_bp = NULL;
	return 0;
}

static int release_device_tx_bpool(struct dpaa_vwd_priv_s  *vwd)
{
	if (!vwd->tx_bp)
		return 0;
	drain_tx_bp_pool(vwd->tx_bp);
	vwd->tx_bp = NULL;
	return 0;
}

/*
 * This function sets the vap fq net_dev with its vap wifi device.
 */
static int set_vap_fqs_netdev(struct vap_desc_s *vap)
{
	int index = 0;
	for (index = 0; index < CDX_VWD_FWD_FQ_MAX; index++)
		vap->wlan_fq_from_fman[index]->net_dev = vap->wifi_dev;
	vap->wlan_fq_to_fman->net_dev = vap->wifi_dev;
	return 0;
}

/*
 * This function resets the vap fq net_dev to NULL.
 */
static int reset_vap_fqs_netdev(struct vap_desc_s *vap)
{
	int index = 0;
	for (index = 0; index < CDX_VWD_FWD_FQ_MAX; index++)
		vap->wlan_fq_from_fman[index]->net_dev = NULL;
	vap->wlan_fq_to_fman->net_dev = NULL;
	return 0;
}

static int vwd_vap_up(struct dpaa_vwd_priv_s *priv, struct vap_desc_s *vap, struct vap_cmd_s *cmd)
{
	struct net_device *wifi_dev;

	wifi_dev = dev_get_by_name(&init_net, cmd->ifname);
	if (!wifi_dev) {
		DPAWIFI_ERROR("%s::No WiFi device %s\n", 
				__func__, &cmd->ifname[0]);
		return -1;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: wifidev found.. %s\n", __FUNCTION__, cmd->ifname);
#endif
	if (!(wifi_dev->flags & IFF_UP)) {
		DPAWIFI_ERROR("%s::WiFi device %s not UP\n",
				__FUNCTION__, &cmd->ifname[0]);
		dev_put(wifi_dev);
		return -1;
	}
#if 0
	//get free vap instance
	if (find_vapdev_by_name(&cmd->ifname[0], &vap)) {
		DPAWIFI_ERROR("%s::device %s already associated\n", 
				__FUNCTION__, &cmd->ifname[0]);
		dev_put(wifi_dev);
		return -1;
	}
	if (!vap) {
		DPAWIFI_ERROR("%s:: no free vap instance for device %s\n", 
				__FUNCTION__, &cmd->ifname[0]);
		dev_put(wifi_dev);
		return -1;
	}
#endif
	if (get_ofport_info(FMAN_IDX, priv->oh_port_handle, &vap->channel, 
				&vap->td[0])) 
	{
		dev_put(wifi_dev);
		return -1;
	}

	vap->ifindex = cmd->ifindex;

	vap->no_l2_itf = cmd->no_l2_itf;
	vap->direct_rx_path = cmd->direct_rx_path;
	vap->direct_tx_path = 0;
	memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
	vap->wifi_dev = wifi_dev;

	/* In struct net_device , wifi_offload_dev field is defined,
	 * using this field to store the vap_desc_t structure pointer
	 */
	wifi_dev->wifi_offload_dev = (struct net_device *)vap;
	vap->vwd = priv;

	dev_put(wifi_dev);
	/* vap->wlan_fq_to_fman is NULL means so far this interface is not up. If it gets up first time
	   it creates all the frame queues. These frame queues can delete only cdx module gets unloaded.*/
	if (!vap->wlan_fq_to_fman)
	{
		/* create frame queues */
		if (create_vap_fqs(vap)) {
			DPAWIFI_ERROR("%s::unable to create vap fqs for device %s\n", 
					__FUNCTION__, &cmd->ifname[0]);
			release_vap_fqs(vap);	
			return -1;
		}
	}
	else
	{
		set_vap_fqs_netdev(vap);
	}
	vap->state = VAP_ST_OPEN;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: UP: name:%s, vapid:%d, direct_rx_path : %s, ifindex:%d, mac:%x:%x:%x:%x:%x:%x\n",
			__func__, vap->ifname, vap->vapid,
			vap->direct_rx_path ? "ON":"OFF", vap->ifindex,
			vap->macaddr[0], vap->macaddr[1],
			vap->macaddr[2], vap->macaddr[3],
			vap->macaddr[4], vap->macaddr[5] );

#endif
	return 0;
}

int vwd_vap_down(struct dpaa_vwd_priv_s *priv , struct vap_desc_s *vap)
{
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:%d\n", __func__, __LINE__);
	DPAWIFI_INFO("%s:DOWN: name:%s, vapid:%d, direct_rx_path : %s, ifindex:%d, mac:%x:%x:%x:%x:%x:%x\n",
			__func__, vap->ifname, vap->vapid,
			vap->direct_rx_path ? "ON":"OFF", vap->ifindex,
			vap->macaddr[0], vap->macaddr[1],
			vap->macaddr[2], vap->macaddr[3],
			vap->macaddr[4], vap->macaddr[5] );
#endif

	reset_vap_fqs_netdev(vap);

	vap->state = VAP_ST_CONFIGURED;

	if(vap->wifi_dev)
		vap->wifi_dev->wifi_offload_dev =  NULL;

	vap->wifi_dev = NULL;
	priv->vap_count--;

	return 0;
}

/** vwd_vap_configure
 *
 */
static int vwd_vap_configure(struct dpaa_vwd_priv_s *priv, struct vap_desc_s *vap, struct vap_cmd_s *cmd)
{
	vap->vapid = cmd->vapid;
	vap->ifindex = cmd->ifindex;
	vap->direct_rx_path = cmd->direct_rx_path;
	vap->direct_tx_path = 0;
	vap->no_l2_itf = cmd->no_l2_itf;
	memcpy(vap->ifname, cmd->ifname, 12);
	memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
	vap->cpu_id = -1;
	vap->state = VAP_ST_CONFIGURED;

	/* Configure sysfs attributes */
	dev_attr_vap[vap->vapid].attr.name=vap->ifname;
	dev_attr_vap[vap->vapid].attr.mode=0444;
	dev_attr_vap[vap->vapid].show=vwd_show_vap_stats;
	dev_attr_vap[vap->vapid].store = NULL;

	return 0;
}

/** dpaa_vwd_handle_vap
 *
 */
int dpaa_vwd_handle_vap( struct dpaa_vwd_priv_s *priv, struct vap_cmd_s *cmd )
{
	int rc = 0, ii;
	struct vap_desc_s *vap;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO( "%s function called %d: %s\n", __func__, cmd->action, cmd->ifname);
#endif
	if (cmd->vapid < 0) {
		DPAWIFI_ERROR("%s : Invalid VAPID (%d)\n", __func__, cmd->vapid);
		return -1;
	}

	if (cmd->vapid >= MAX_WIFI_VAPS) {
		DPAWIFI_ERROR("%s : VAPID (%d)  >=  MAX_WIFI_VAPS(%d)\n", __func__, cmd->vapid, MAX_WIFI_VAPS);
		return -1;
	}

	spin_lock_bh(&priv->vaplock);
	vap = &priv->vaps[cmd->vapid];
	switch (cmd->action) {
		case CONFIGURE:
			DPAWIFI_INFO("%s: CONFIGURE ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_CLOSE) {
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not in close state\n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}

			if (!(rc = vwd_vap_configure(priv, vap, cmd)))
			{
				DPAWIFI_INFO("%s: Configured VAP (id : %d  name : %s)\n", __func__, cmd->vapid, cmd->ifname);

                                spin_unlock_bh(&priv->vaplock);
                                /* Create sysfs entry for vap interface */
                                if(device_create_file(priv->vwd_device, &dev_attr_vap[cmd->vapid])) {
                                        DPAWIFI_ERROR("%s::unable to create sysfs entry for vap iface %s\n",
                                                        __FUNCTION__, cmd->ifname);
                                }
                                spin_lock_bh(&priv->vaplock);

			}
			else
			{
				DPAWIFI_ERROR("%s: Failed to configure VAP (id : %d  name : %s)\n",
						__func__, cmd->vapid, cmd->ifname);
			}
			break;


		case ADD:
			DPAWIFI_INFO("%s: ADD ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_CONFIGURED) {
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not configured \n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}


			rc = vwd_vap_up(priv,vap,cmd);
			if (rc < 0)
			{
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not UP \n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
			}
			break;
		case REMOVE:
			DPAWIFI_INFO("%s: REMOVE ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_OPEN) {
				DPAWIFI_INFO("%s : VAP (id : %d  name : %s) is not opened \n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}
			vwd_vap_down(priv, vap);

			break;
		case UPDATE:
			DPAWIFI_INFO("%s: UPDATE ... %s\n", __func__, cmd->ifname);
			vap->ifindex = cmd->ifindex;
			vap->direct_rx_path = cmd->direct_rx_path;
			vap->no_l2_itf = cmd->no_l2_itf;
			memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
			break;		
		case RESET:
			DPAWIFI_INFO("%s: RESET ...\n", __func__);
			for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
				vap = &priv->vaps[ii];

				if (vap->state == VAP_ST_CLOSE)
					continue;

				if (vap->state == VAP_ST_OPEN)
					vwd_vap_down(priv, vap);
				if (vap->state == VAP_ST_CONFIGURED) {
					vap->state = VAP_ST_CLOSE;
				}
			}
			break;

		default:
			DPAWIFI_INFO("%s::unhandled cmd %d\n", __FUNCTION__, cmd->action);	
			rc = -1;
			break;
	}

	spin_unlock_bh(&priv->vaplock);
	return rc;

}

/** vwd_open
 *
 */
static int dpaa_vwd_open(struct inode *inode, struct file *file)
{
#if 0
	//allow only one open instance
	if (!atomic_dec_and_test(&dpa_vwd_open_count)) {
		atomic_inc(&dpa_vwd_open_count);
		return -EBUSY;
	}
#endif
	int result = 0;
	unsigned dev_minor = iminor(inode);

#if defined (CONFIG_VWD_MULTI_MAC)
	DPAWIFI_INFO("%s :  Multi MAC mode enabled\n", __func__);
#endif
	DPAWIFI_INFO( "%s :  minor device -> %d\n", __func__, dev_minor);
	if (dev_minor != 0)
	{
		DPAWIFI_INFO(KERN_ERR ": trying to access unknown minor device -> %d\n", dev_minor);
		result = -ENODEV;
		goto out;
	}

	file->private_data = &vwd;

out:
	return result;

	return 0;
}

/** vwd_close
 *
 */
static int dpaa_vwd_close(struct inode * inode, struct file * file)
{
	DPAWIFI_INFO("%s TODO \n", __func__);
#if 0
	//TBD - recover resources here
	atomic_inc(&dpa_vwd_open_count);
#endif
	return 0;
}


#define SIOCVAPUPDATE  ( 0x6401 )

/**dpaa_vwd_ioctl
 *
 */
long dpaa_vwd_ioctl(struct file * file, unsigned int cmd, unsigned long arg)
{
	struct vap_cmd_s vap_cmd;
	void __user *argp = (void __user *)arg;
	int rc = -EOPNOTSUPP;
	struct dpaa_vwd_priv_s *priv = (struct dpaa_vwd_priv_s *)file->private_data;

	rtnl_lock();
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s vapcmd recvd:%x \n", __func__, cmd);
#endif
	switch(cmd) {
		case SIOCVAPUPDATE:
			if (copy_from_user(&vap_cmd, argp, sizeof(struct vap_cmd_s))) {
				rc = -EFAULT;
				goto done;
			}

			rc = dpaa_vwd_handle_vap(priv, &vap_cmd);
	}
done:
	rtnl_unlock();
	return rc;
}

static int vwd_init_ohport(struct dpaa_vwd_priv_s *priv)
{
	int handle;

	/* Get OH port for this driver */
	handle = alloc_offline_port(FMAN_IDX, PORT_TYPE_WIFI, vwd_rx_exception_pkt, NULL);
	if (handle < 0)
	{
		DPAWIFI_ERROR("%s: Error in allocating OH port Channel\n", __func__);
		return -1;
	}
	priv->oh_port_handle = handle;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: allocated oh port %d\n", __func__, priv->oh_port_handle);
#endif

#ifdef DPA_SG_SUPPORT
	/* Disable DMA write optimization for WiFi offline port dpa-fman0-oh@3 to avoid
	   corrupting the unaligned aggregated skb cloned packets */
	if(ohport_set_dma(priv->oh_port_handle, 0) == -1)
	{
		DPAWIFI_ERROR("%s: Error in disabling DMA write optimization\n", __func__);
	}
#endif

	//change ofne for this port to parser, no need to get to ucode for SEC Error check.
	return(ohport_set_ofne(priv->oh_port_handle, 0x440000));
}

static void vwd_release_pcd_fqs(struct dpaa_vwd_priv_s *priv)
{
	struct qman_fq* fq;
	struct dpa_fq* dpafq;
	int i;

	if (priv->wlan_exception_fq)
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:: releasing expt fq :%d\n", __func__, priv->expt_fq_count);
#endif
		dpafq = priv->wlan_exception_fq;
		for (i = 0; i < priv->expt_fq_count; i++)
		{
			fq= &dpafq->fq_base;
			vwd_fq_destroy(fq);
			dpafq++;
		}
		kfree(priv->wlan_exception_fq);
		priv->wlan_exception_fq = NULL;
	}

	return;
}

static int vwd_init_stats(struct dpaa_vwd_priv_s *priv)
{
	int i = 0;

	/* Allocate per cpu structure for each vap */
	for (i = 0; i< MAX_WIFI_VAPS; i++) {
		priv->vaps[i].vap_stats = alloc_percpu(struct vap_stats_s);
		if (!priv->vaps[i].vap_stats)
			return -1;
	}

	/* Allocate per cpu structure for vwd global stats */
	priv->vwd_global_stats = alloc_percpu(struct vwd_global_stats_s);
	if (!priv->vwd_global_stats)
		return -1;
	return 0;
}

static void vwd_release_stats(struct dpaa_vwd_priv_s *priv)
{
	int i = 0;
	/* Free up the per cpu structure of each vap */
	for (i = 0; i< MAX_WIFI_VAPS; i++) {
		if (priv->vaps[i].vap_stats) {
			free_percpu(priv->vaps[i].vap_stats);
			priv->vaps[i].vap_stats = NULL;
		}
	}

	/* Free up the per cpu structure of vwd global stats */
	if (priv->vwd_global_stats) {
		free_percpu(priv->vwd_global_stats);
		priv->vwd_global_stats = NULL;
	}
}

static int vwd_free_ohport(struct dpaa_vwd_priv_s *priv)
{

	int rc;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: releasing oh port %d\n", __func__, priv->oh_port_handle);
#endif
	rc = release_offline_port(FMAN_IDX, priv->oh_port_handle);
	if (rc < 0)
	{
		DPAWIFI_ERROR("%s: Error in releasing OH port Channel\n", __func__);
		return -1;
	}

	return 0;
}

/*
 * vwd_wifi_if_send_pkt
 */
static int vwd_wifi_if_send_pkt(struct sk_buff *skb)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct vap_desc_s *vap;
	int rc = -1;

	if (!priv->fast_path_enable || (eth_hdr(skb)->h_dest[0] & 0x1))
	{
		goto end;
	}

	spin_lock_bh(&priv->vaplock);
	vap = (struct vap_desc_s *)skb->dev->wifi_offload_dev;

	if (vap && (vap->ifindex == skb->dev->ifindex) && vap->direct_rx_path && (vap->state == VAP_ST_OPEN))
	{
		spin_unlock_bh(&priv->vaplock);
		INCR_PER_CPU_STAT(priv->vaps[vap->vapid].vap_stats, pkts_direct_rx);
		skb_push(skb, ETH_HLEN);
		spin_lock_bh(&priv->txlock);
		dpaa_vwd_send_packet( priv, &priv->vaps[vap->vapid], skb);
		spin_unlock_bh(&priv->txlock);
		rc = 0;
	}
	else
		spin_unlock_bh(&priv->vaplock);
end:
	return rc;
}

/** dpaa_vwd_up
 *
 */
static int dpaa_vwd_up(struct dpaa_vwd_priv_s *priv )
{
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::\n", __func__);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	nf_register_net_hook(&init_net, &vwd_hook);
	nf_register_net_hook(&init_net, &vwd_hook_ipv6);
	nf_register_net_hook(&init_net, &vwd_hook_bridge);
#else
	nf_register_hook(&vwd_hook);
	nf_register_hook(&vwd_hook_ipv6);
	nf_register_hook(&vwd_hook_bridge);
#endif

	priv->fast_path_enable = 1;
	if (dpaa_vwd_sysfs_init(priv))
		goto err0;
	wifi_rx_fastpath_register(vwd_wifi_if_send_pkt);
#if 0
	if (vwd_ofld == PFE_VWD_NAS_MODE) {
		register_netdevice_notifier(&vwd_vap_notifier);
	}

	/* supported features */
	priv->vap_dev_hw_features =
		NETIF_F_RXCSUM | NETIF_F_IP_CSUM |  NETIF_F_IPV6_CSUM |
		NETIF_F_SG | NETIF_F_TSO;

	/* enabled by default */
	if (lro_mode) {
		priv->vap_dev_hw_features |= NETIF_F_LRO;
	}

	priv->vap_dev_features = priv->vap_dev_hw_features;
#endif

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: End\n", __func__);
#endif
	return 0;

err0:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	nf_unregister_net_hook(&init_net, &vwd_hook);
	nf_unregister_net_hook(&init_net, &vwd_hook_ipv6);
	nf_unregister_net_hook(&init_net, &vwd_hook_bridge);
#else
	nf_unregister_hook(&vwd_hook);
	nf_unregister_hook(&vwd_hook_ipv6);
	nf_unregister_hook(&vwd_hook_bridge);
#endif

	return -1;

}

/** dpaa_vwd_down
 *
 */
int dpaa_vwd_down( struct dpaa_vwd_priv_s *priv )
{
	int ii;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO( "%s: %s\n", priv->name, __func__);
#endif
	wifi_rx_fastpath_unregister();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	nf_unregister_net_hook(&init_net, &vwd_hook);
	nf_unregister_net_hook(&init_net, &vwd_hook_ipv6);
	nf_unregister_net_hook(&init_net, &vwd_hook_bridge);
#else
	nf_unregister_hook(&vwd_hook);
	nf_unregister_hook(&vwd_hook_ipv6);
	nf_unregister_hook(&vwd_hook_bridge);
#endif

	for (ii = 0; ii < MAX_WIFI_VAPS; ii++)
	{
		struct vap_desc_s *vap = &priv->vaps[ii];
		struct net_device *wifi_dev = NULL;

		if (vap->state == VAP_ST_OPEN) {
			vwd_vap_down(priv, vap);
		}
		release_vap_fqs(vap);

		if (vap->state == VAP_ST_CONFIGURED) {

			wifi_dev = dev_get_by_name(&init_net, vap->ifname);

			if (wifi_dev) {
				/* In struct net_device , wifi_offload_dev field is defined,
				 * using this field to store the vap_desc_t structure pointer
				 */
				wifi_dev->wifi_offload_dev = NULL;
#if 0
				if (wifi_dev->wifi_offload_dev) {
					wifi_dev->ethtool_ops = vap->wifi_ethtool_ops;
					wifi_dev->wifi_offload_dev = NULL;
					wifi_dev->hw_features = vap->wifi_hw_features;
					wifi_dev->features = vap->wifi_features;
				}
#endif
				dev_put(wifi_dev);
			}

#if 0
			sysfs_remove_group(vap->vap_kobj, &vap_attr_group);
			kobject_put(vap->vap_kobj);
			dev_deactivate(vap->dev);
			unregister_netdev(vap->dev);
			free_netdev(vap->dev);
#endif
			vap->state = VAP_ST_CLOSE;
		}
	}

#if 0
	if (vwd_ofld == PFE_VWD_NAS_MODE) {
		unregister_netdevice_notifier(&vwd_vap_notifier);
	}
#endif

	priv->vap_count = 0;
	dpaa_vwd_sysfs_exit();

	return 0;
}

/** dpaa_vwd_driver_init
 *
 *       DPAA wifi offload:
 *       -
 */

int dpaa_vwd_driver_init( struct dpaa_vwd_priv_s *priv )
{
	int rc;

	strcpy(priv->name, "vwd");
	spin_lock_init(&priv->vaplock);
	spin_lock_init(&priv->txlock);
	rc = dpaa_vwd_up(priv);
	return rc;
}

/** vwd_driver_remove
 *
 */
static int dpaa_vwd_driver_remove(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	dpaa_vwd_down(priv);
	return 0;
}

/**dpaa_vwd_init
 *
 */
int dpaa_vwd_init(void)
{
	struct dpaa_vwd_priv_s  *priv = &vwd;
	int rc = 0;

	memset(priv, 0, sizeof(*priv));
	DPAWIFI_INFO("%s::!!!!!!!!!!!!!! Buffer copy disabled !!!!!!!!!!!!!!!\n", __FUNCTION__);
	DPAWIFI_INFO("%s::!!!!!!!!!!!!!! Wifi Perf image !!!!!!!!!!!!!!!\n", __FUNCTION__);
	priv->vwd_major = register_chrdev(0,"vwd",&vwd_fops);
	if (priv->vwd_major < 0)
	{
		DPAWIFI_ERROR("%s register_chrdev failed\n",__func__);
		goto err0;	
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: created vwd device(%d, 0)\n", __func__, priv->vwd_major );
#endif
	priv->vwd_class = class_create(THIS_MODULE, "vwd");
	if (priv->vwd_class == NULL)
	{
		DPAWIFI_ERROR("%s class_create failed\n",__func__);
		goto err1;	
	}

	priv->vwd_device = device_create(priv->vwd_class, NULL, MKDEV(priv->vwd_major,0), NULL, "vwd0");
	if (priv->vwd_device == NULL)
	{
		DPAWIFI_ERROR("%s class_create failed\n",__func__);
		goto err2;	
	}

	if( dpaa_vwd_driver_init( priv ) )
	{
		DPAWIFI_ERROR("%s dpaa_vwd_driver_init failed\n",__func__);
		goto err3;
	}

	rc = vwd_init_ohport(priv);
	if (rc < 0)
	{
		DPAWIFI_ERROR("%s: vwd_init_ohport failed\n",__func__);
		goto err4;
	}

	rc = vwd_init_pcd_fqs(priv);
	if (rc < 0)
	{
		DPAWIFI_ERROR("%s: vwd_init_pcd_fqs failed\n",__func__);
		goto err5;
	}

	vwd.eth_priv = get_eth_priv("eth0");
	if (!vwd.eth_priv)
	{
		DPAWIFI_ERROR("%s: eth_priv failed\n",__func__);
		goto err6;
	}

	if (add_device_tx_done_bpool(priv))
	{
		DPAWIFI_ERROR("%s::unable to create  device tx done bpool %s\n", __FUNCTION__, priv->name);
		goto err7;
	}

	if (add_device_tx_bpool(priv))
	{
		DPAWIFI_ERROR("%s::unable to create  device tx bpool %s\n", __FUNCTION__, priv->name);
		goto err8;
	}

	if (dpa_register_wifi_xmit_local_hook(vwd_xmit_local_packet) < 0)
	{
		DPAWIFI_ERROR("%s::unable to create  device tx bpool %s\n", __FUNCTION__, priv->name);
		goto err9;
	}

	/* vwd stats init*/
	rc = vwd_init_stats(priv);
        if (rc < 0)
        {
                DPAWIFI_ERROR("%s: vwd_init_stats failed\n",__func__);
                goto err10;
        }

	DPAWIFI_INFO("%s: INIT successful\n", __func__ );
	register_cdx_deinit_func(dpaa_vwd_exit);
	return rc;
err10:
	vwd_release_stats(priv);
err9:
	release_device_tx_bpool(priv);
err8:
	release_device_tx_done_bpool(priv);
err7: 
	vwd.eth_priv = NULL;
err6:
	vwd_release_pcd_fqs(priv);
err5:
	release_offline_port(FMAN_IDX, priv->oh_port_handle);
err4: 
	dpaa_vwd_driver_remove();
err3:
	device_destroy(priv->vwd_class, MKDEV(priv->vwd_major, VWD_MINOR));
	priv->vwd_device = NULL;
err2:
	class_destroy(priv->vwd_class);
	priv->vwd_class = NULL;
err1:
	unregister_chrdev(priv->vwd_major, "vwd");
	priv->vwd_major = 0;
err0:
	return -1;
}


/** dpaa_vwd_exit
 *
 */
void dpaa_vwd_exit(void)
{
	struct dpaa_vwd_priv_s  *priv = &vwd;

	printk("%s::\n", __FUNCTION__);
	dpa_unregister_wifi_xmit_local_hook();
	release_device_tx_bpool(priv);
	release_device_tx_done_bpool(priv);

	if(priv->eth_priv)
	{
		dev_put(priv->eth_priv->net_dev);
		priv->eth_priv = NULL;
	}
	vwd_release_pcd_fqs(priv);
	/* Release OH port here */
	vwd_free_ohport(priv);	
	//TODO ensure all vaps are down
	dpaa_vwd_driver_remove();
	device_destroy(priv->vwd_class, MKDEV(priv->vwd_major, VWD_MINOR));
	unregister_chrdev(priv->vwd_major, "vwd");
	class_destroy(priv->vwd_class);
}

#else /* !CFG_WIFI_OFFLOAD */

/** pfe_vwd_init
 *
 */
int pfe_vwd_init(struct pfe *pfe)
{
	DPAWIFI_INFO(KERN_INFO "%s\n", __func__);
	return 0;
}

/** pfe_vwd_exit
 *
 */
void pfe_vwd_exit(struct pfe *pfe)
{
	DPAWIFI_INFO(KERN_INFO "%s\n", __func__);
}

#endif /* !CFG_WIFI_OFFLOAD */

